//! Inner loop only: in-process speakers; not acceptance evidence for T6-1..T6-5.
//!
//! The lane's safety gates, driven the way the engine drives them: **C8** (a dry
//! run opens no socket), **C9** (every refusal opens no socket), **C10** (a
//! wildcard interface entry authorises, a literal one does not), **C15** (the
//! four ceilings: cases per job, bytes per second, concurrent connections, and
//! the message size), **C16** (ids are stable and repeat elements are capped)
//! and **C18** (the core's own listener ports are never addressed). Spec S7 is
//! the dry run.
//!
//! Every test that needs a real port binds an ephemeral one through
//! [`common::bind_or_skip`], which prints `SKIP: sandbox refuses local binding`
//! and makes the test return; where a port *can* be bound the test asserts and
//! fails loudly. Most tests here need no port at all: a refusal, a dry run and a
//! ceiling are all decided before a socket would be opened, which is the point.

mod common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aitm_proto_l4::config::L4Config;
use aitm_proto_l4::guard::{L4Guard, ANY_INTERFACE};
use aitm_proto_l4::types::{
    IpCidr, L4Capability, L4Direction, L4ScopeEntry, L4ScopeId, L4ScopeSource, PortRange, RateCap,
};
use aitm_scan_l4_stream::client::testing::CountingClient;
use aitm_scan_l4_stream::client::StreamClient;
use aitm_scan_l4_stream::codec::encode_hex;
use aitm_scan_l4_stream::host::HostError;
use aitm_scan_l4_stream::state::{
    MAX_BYTES_PER_S, MAX_CASES_PER_JOB, MAX_CONNECTIONS, MAX_MESSAGE, MAX_REPEAT_INDEX,
};
use aitm_scan_l4_stream::{lane_with_client, L4StreamLane};
use aitm_scan_model::{
    builtin_profiles, Check, Discovery, JobCtx, L4Seed, L4TargetSpec, L4Transport, Lane, Outcome,
    Payload, PayloadMode, ProfileTarget, ScanProfile,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use common::TestJob;

// ---------------------------------------------------------------------------
// Scaffolding
// ---------------------------------------------------------------------------

/// The built-in `l4-stream-safe` profile, which is what an operator runs.
fn safe_profile() -> ScanProfile {
    builtin_profiles()
        .into_iter()
        .find(|profile| profile.name == "l4-stream-safe")
        .expect("`l4-stream-safe` is a built-in profile")
}

/// `l4-stream-safe` over one endpoint, with the case budget, grammar and seeds
/// a test needs.
fn profile_for(
    ip: &str,
    port: u16,
    grammar: Option<&str>,
    cases: u32,
    seeds: &[String],
) -> ScanProfile {
    let mut profile = safe_profile();
    profile.l4.cases = cases;
    profile.l4.seeds = seeds
        .iter()
        .map(|hex| L4Seed::Hex { hex: hex.clone() })
        .collect();
    profile.target = ProfileTarget {
        origins: Vec::new(),
        l4: vec![L4TargetSpec {
            ip: ip.to_string(),
            port,
            proto: L4Transport::Tcp,
            grammar: grammar.map(str::to_string),
        }],
    };
    profile
}

/// Seeds as the profile carries them: lowercase hex of the given byte strings.
fn hex_seeds(seeds: &[&[u8]]) -> Vec<String> {
    seeds.iter().map(|bytes| encode_hex(bytes)).collect()
}

/// One scope entry, written the way an operator's config does.
fn entry(addr: Ipv4Addr, prefix: u8, interface: &str, capability: L4Capability) -> L4ScopeEntry {
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
            pps: 10_000,
            burst: 10_000,
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

/// A payload carrying `bytes` at the point.
fn payload(bytes: &[u8]) -> Payload {
    Payload {
        value: String::new(),
        mode: PayloadMode::Replace,
        bytes: Some(bytes.to_vec()),
    }
}

/// The lane's check with this catalogue id.
fn check_by_id(checks: &[Arc<dyn Check>], id: &str) -> Arc<dyn Check> {
    checks
        .iter()
        .find(|check| check.meta().id == id)
        .unwrap_or_else(|| panic!("the lane ships a `{id}` check"))
        .clone()
}

/// The `<planned>` of the S6.5 detail's `cases=<sent>/<planned>` clause.
fn planned_in(detail: &str) -> u32 {
    let clause = detail
        .split_whitespace()
        .find_map(|word| word.strip_prefix("cases="))
        .unwrap_or_else(|| panic!("the detail has no `cases=` clause: {detail}"));
    let (_sent, planned) = clause
        .split_once('/')
        .unwrap_or_else(|| panic!("`cases={clause}` is not `<sent>/<planned>`: {detail}"));
    planned
        .parse()
        .unwrap_or_else(|e| panic!("`{planned}` is not a case count ({e}): {detail}"))
}

/// Discover under `profile`, through `client`, against `guard`.
async fn discover_with(
    guard: Option<Arc<L4Guard>>,
    client: Arc<CountingClient>,
    profile: ScanProfile,
    job_id: &str,
) -> (
    Arc<L4StreamLane>,
    Arc<dyn JobCtx>,
    anyhow::Result<Discovery>,
) {
    let target = profile.target.clone();
    let lane = lane_with_client(guard, None, Arc::clone(&client) as Arc<dyn StreamClient>);
    let job: Arc<dyn JobCtx> = Arc::new(
        TestJob::new(profile)
            .with_job_id(job_id)
            .with_marker(&format!("aitm{job_id}")),
    );
    let found = lane.discover(&target, job.as_ref()).await;
    (lane, job, found)
}

// ---------------------------------------------------------------------------
// A speaker that holds each connection open
// ---------------------------------------------------------------------------

/// An in-process TCP speaker that accepts, reads one message, holds the
/// connection `hold` long, then echoes and closes.
///
/// Task 21's speakers all mimic a T10 trigger; this one mimics nothing — it
/// exists so a test can watch how many connections the lane holds at once
/// (C15's four-connection ceiling) and whether a refusal let one through at all
/// (C9, C10, C18). The live counter is decremented *before* the reply is
/// written, so the high-water mark can never over-count a connection the lane
/// has already been released from.
struct Holder {
    /// Where the lane reaches it.
    addr: SocketAddr,
    /// Connections accepted since it started.
    accepts: Arc<AtomicU32>,
    /// The most connections it ever held at once.
    max_concurrent: Arc<AtomicU32>,
}

impl Holder {
    fn accepts(&self) -> u32 {
        self.accepts.load(Ordering::SeqCst)
    }

    fn max_concurrent(&self) -> u32 {
        self.max_concurrent.load(Ordering::SeqCst)
    }
}

/// The port a socket-free test names: nothing of this harness listens on it,
/// and no test that uses it ever reaches the wire — a refusal, a dry run, a
/// passed deadline or a client double stops every one of them first.
const UNBOUND: u16 = 9000;

/// A speaker and its port, or the socket-free fallback.
///
/// A sandbox that refuses to bind leaves the speaker `None` and names
/// [`UNBOUND`], so the half of a test that opens no socket — which is most of
/// what C8, C9, C15, C16 and C18 are about — still runs and still asserts. The
/// connection counters are then the only thing not checked, and
/// [`accepts_is`] skips exactly those.
async fn holder_or_unbound(hold: Duration) -> (Option<Holder>, u16) {
    match holder(hold).await {
        Some(speaker) => {
            let port = speaker.addr.port();
            (Some(speaker), port)
        }
        None => (None, UNBOUND),
    }
}

/// Assert the speaker accepted `want` connections, when a speaker was bound.
fn accepts_is(speaker: Option<&Holder>, want: u32, what: &str) {
    if let Some(speaker) = speaker {
        assert_eq!(speaker.accepts(), want, "{what}");
    }
}

/// A [`Holder`] on an ephemeral loopback port, or `None` when the sandbox
/// refuses to bind.
async fn holder(hold: Duration) -> Option<Holder> {
    let listener: TcpListener = common::bind_or_skip().await?;
    let addr = match listener.local_addr() {
        Ok(addr) => addr,
        Err(e) => panic!("a bound loopback listener has a local address: {e}"),
    };
    let accepts = Arc::new(AtomicU32::new(0));
    let live = Arc::new(AtomicU32::new(0));
    let max_concurrent = Arc::new(AtomicU32::new(0));
    let speaker = Holder {
        addr,
        accepts: Arc::clone(&accepts),
        max_concurrent: Arc::clone(&max_concurrent),
    };

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _peer)) = listener.accept().await else {
                return;
            };
            accepts.fetch_add(1, Ordering::SeqCst);
            let held = live.fetch_add(1, Ordering::SeqCst) + 1;
            max_concurrent.fetch_max(held, Ordering::SeqCst);
            let live = Arc::clone(&live);
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                let read = stream.read(&mut buf).await.unwrap_or(0);
                tokio::time::sleep(hold).await;
                // Release the count first: the lane's connection permit is only
                // freed once it has the reply, so a connection counted here is
                // always one the lane is still holding.
                live.fetch_sub(1, Ordering::SeqCst);
                let _ = stream.write_all(buf.get(..read).unwrap_or(b"")).await;
                let _ = stream.flush().await;
            });
        }
    });

    Some(speaker)
}

// ---------------------------------------------------------------------------
// C8 / S7: a dry run opens no socket
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn dry_run_opens_no_socket() {
    // A dry run opens nothing, so the speaker is here only to be ignored.
    let speaker = common::tlv_crash(Duration::from_secs(1)).await;
    let port = speaker.as_ref().map_or(UNBOUND, |s| s.addr.port());

    // The guard authorises the endpoint for discovery's S5.2 step-1 preview,
    // and is then emptied: from here on *any* `guard.check` refuses, so a
    // single byte on the wire would surface as a `Guard` stop reason.
    let guard = common::wildcard_guard(&[port]);
    let mut profile = profile_for("127.0.0.1", port, Some("raw"), 100, &hex_seeds(&[b"abc"]));
    profile.l4.dry_run = true;

    let client = Arc::new(CountingClient::dry_run());
    let (lane, job, found) = discover_with(
        Some(Arc::clone(&guard)),
        Arc::clone(&client),
        profile,
        "22dry",
    )
    .await;
    let discovery = found.expect("discovery over a scoped loopback endpoint succeeds");
    assert_eq!(
        discovery.points.len(),
        1,
        "one `raw` seed is one point: {:?}",
        discovery
            .points
            .iter()
            .map(|point| point.path.clone())
            .collect::<Vec<_>>()
    );

    for existing in guard.list_scope() {
        assert!(guard.remove_scope(existing.id), "the entry was there");
    }
    assert!(
        guard.list_scope().is_empty(),
        "the dry run runs against an empty scope"
    );

    let point = &discovery.points[0];
    let host = lane
        .probe_host_for(point, Arc::clone(&job))
        .expect("the lane hosts probes for a point it discovered");
    let verdict = check_by_id(&lane.checks(), "l4-crash")
        .run(point, host.as_ref())
        .await;

    assert_eq!(verdict.outcome, Outcome::Inconclusive, "{}", verdict.detail);
    assert!(
        verdict.detail.starts_with("dry run: 100 cases"),
        "{}",
        verdict.detail
    );
    let rendered = verdict
        .detail
        .lines()
        .filter(|line| line.starts_with('#'))
        .count();
    assert_eq!(rendered, 50, "{}", verdict.detail);

    // Nothing was sent, so the empty scope never bit: no guard refusal reached
    // the verdict, no exchange was opened, and the speaker saw no connection.
    assert!(
        !verdict.detail.contains("guard refused"),
        "a dry run never asks the guard: {}",
        verdict.detail
    );
    assert_eq!(client.count(), 0, "a dry run opens no exchange");
    if let Some(speaker) = speaker.as_ref() {
        assert_eq!(speaker.accepts(), 0, "a dry run opens no socket");
    }
}

// ---------------------------------------------------------------------------
// C9: every refusal opens no socket
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn refusals_open_no_socket() {
    let (speaker, port) = holder_or_unbound(Duration::ZERO).await;
    let seeds = hex_seeds(&[b"abc"]);

    // The shipped constructor with no guard: L4 is disabled.
    let disabled = aitm_scan_l4_stream::lane(None, None).expect("the lane is Some even so");
    let profile = profile_for("127.0.0.1", port, Some("raw"), 10, &seeds);
    let target = profile.target.clone();
    let job = TestJob::new(profile).with_job_id("22off");
    let error = disabled
        .discover(&target, &job)
        .await
        .expect_err("a disabled L4 subsystem sends nothing");
    assert_eq!(
        error.to_string(),
        "scan: refused_l4: L4 is disabled (l4.enabled: false); the stream lane sends nothing"
    );

    // The same refusal through a *live* client, which would really connect to
    // the speaker if the lane let it.
    let cases: Vec<(&str, Option<Arc<L4Guard>>, &str)> = vec![
        ("disabled", None, "scan: refused_l4: "),
        (
            "other CIDR",
            Some(guard_over(vec![entry(
                Ipv4Addr::new(10, 0, 0, 0),
                8,
                ANY_INTERFACE,
                L4Capability::Inject,
            )])),
            "scan: out_of_scope: ",
        ),
        (
            "capture only",
            Some(guard_over(vec![entry(
                Ipv4Addr::new(127, 0, 0, 0),
                8,
                ANY_INTERFACE,
                L4Capability::Capture,
            )])),
            "scan: out_of_scope: ",
        ),
    ];

    for (name, guard, prefix) in cases {
        let client = Arc::new(CountingClient::live());
        let profile = profile_for("127.0.0.1", port, Some("raw"), 10, &seeds);
        let (_lane, _job, found) =
            discover_with(guard, Arc::clone(&client), profile, "22refuse").await;
        let error = found
            .err()
            .unwrap_or_else(|| panic!("the `{name}` guard must refuse"));
        let text = error.to_string();
        assert!(text.starts_with(prefix), "{name}: {text}");
        if name == "capture only" {
            assert!(text.contains("capability"), "{name}: {text}");
        }
        assert_eq!(client.count(), 0, "{name}: a refusal opens no exchange");
    }

    accepts_is(speaker.as_ref(), 0, "a refusal opens no socket");
}

// ---------------------------------------------------------------------------
// C10: a wildcard interface entry authorises, a literal one does not
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn wildcard_authorises_literal_refuses() {
    let (speaker, port) = holder_or_unbound(Duration::ZERO).await;
    let seeds = hex_seeds(&[b"abc"]);

    // `"*"`: the preview passes and one real probe reaches the speaker. This
    // half needs a bound port — it is the one place in this file that puts a
    // byte on the wire — so without one it is left to the Terminal run.
    if let Some(speaker) = speaker.as_ref() {
        let client = Arc::new(CountingClient::live());
        let profile = profile_for("127.0.0.1", port, Some("raw"), 10, &seeds);
        let (lane, job, found) = discover_with(
            Some(common::wildcard_guard(&[port])),
            Arc::clone(&client),
            profile,
            "22wild",
        )
        .await;
        let discovery = found.expect("the wildcard entry authorises the preview");
        let point = &discovery.points[0];
        let host = lane
            .probe_host_for(point, Arc::clone(&job))
            .expect("the lane hosts the point");
        host.probe(&payload(b"abc"))
            .await
            .expect("an authorised probe reaches the speaker");
        assert_eq!(client.count(), 1, "one probe is one exchange");
        assert_eq!(speaker.accepts(), 1, "one probe is one connection");
    }

    // `"lo0"`: a socket client cannot promise an egress interface, so a literal
    // entry authorises nothing and no second connection is made.
    let literal = Arc::new(CountingClient::live());
    let profile = profile_for("127.0.0.1", port, Some("raw"), 10, &seeds);
    let (_lane, _job, found) = discover_with(
        Some(guard_over(vec![entry(
            Ipv4Addr::new(127, 0, 0, 0),
            8,
            "lo0",
            L4Capability::Inject,
        )])),
        Arc::clone(&literal),
        profile,
        "22lo0",
    )
    .await;
    let error = found.expect_err("a literal interface entry does not cover the wildcard");
    assert!(
        error.to_string().starts_with("scan: out_of_scope: "),
        "{error}"
    );
    assert_eq!(literal.count(), 0, "a refusal opens no exchange");
    accepts_is(
        speaker.as_ref(),
        1,
        "the refused lane added no connection of its own",
    );
}

// ---------------------------------------------------------------------------
// C15: the four ceilings
// ---------------------------------------------------------------------------
//
// One test each, so that the three that need no socket still assert where the
// sandbox refuses to bind — only the connection ceiling needs a real speaker.

/// (1) Cases per job: a profile asking for a million over three points plans
/// at most the lane's own ceiling in total.
///
/// The job's deadline has already passed, so every campaign stops at its
/// first case: the planned count is what is under test, not a million real
/// sends.
#[tokio::test(flavor = "multi_thread")]
async fn ceiling_cases_per_job() {
    let seeds = hex_seeds(&[b"aaa", b"bbb", b"ccc"]);
    let client = Arc::new(CountingClient::dry_run());
    let mut profile = profile_for("127.0.0.1", 9000, Some("raw"), 999_999, &seeds);
    profile.l4.max_bytes_per_s = 1_000_000_000;
    let target = profile.target.clone();
    let lane = lane_with_client(
        Some(common::wildcard_guard(&[9000])),
        None,
        Arc::clone(&client) as Arc<dyn StreamClient>,
    );
    let job: Arc<dyn JobCtx> = Arc::new(
        TestJob::new(profile)
            .with_job_id("22cap")
            .with_marker("aitm22cap")
            .with_deadline(Instant::now() - Duration::from_secs(1)),
    );
    let discovery = lane
        .discover(&target, job.as_ref())
        .await
        .expect("three `raw` seeds over a scoped endpoint");
    assert_eq!(discovery.points.len(), 3, "three seeds are three points");

    let crash = check_by_id(&lane.checks(), "l4-crash");
    let mut total_planned = 0u32;
    for point in &discovery.points {
        let host = lane
            .probe_host_for(point, Arc::clone(&job))
            .expect("the lane hosts the point");
        let verdict = crash.run(point, host.as_ref()).await;
        total_planned += planned_in(&verdict.detail);
    }
    assert!(
        total_planned <= MAX_CASES_PER_JOB,
        "three points planned {total_planned} cases, over the {MAX_CASES_PER_JOB} lane cap"
    );
    assert_eq!(total_planned, 4998, "5000 / 3 points, three times");
    assert_eq!(client.count(), 0, "a passed deadline opens no exchange");
}

/// (2) Bytes per second: a gigabyte-per-second profile is paced at 1 MiB/s.
///
/// The pacer is the job's, built at discovery, so no socket is needed to read
/// the rate it was clamped to.
#[tokio::test(flavor = "multi_thread")]
async fn ceiling_bytes_per_second() {
    let mut profile = profile_for("127.0.0.1", 9000, Some("raw"), 10, &hex_seeds(&[b"aaa"]));
    profile.l4.max_bytes_per_s = 1_000_000_000;
    let (lane, _job, found) = discover_with(
        Some(common::wildcard_guard(&[9000])),
        Arc::new(CountingClient::dry_run()),
        profile,
        "22rate",
    )
    .await;
    found.expect("one `raw` seed over a scoped endpoint");

    let state = lane.state().get("22rate").expect("discovery left state");
    let rate = state
        .pacer
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .rate();
    assert_eq!(rate, MAX_BYTES_PER_S);
    assert_eq!(rate, 1_048_576);
}

/// (3) Concurrent connections: eight probes from eight hosts of one job never
/// hold more than four connections at once.
///
/// The one ceiling that needs a real speaker, so the one that is left to the
/// Terminal run where the sandbox refuses to bind.
#[tokio::test(flavor = "multi_thread")]
async fn ceiling_concurrent_connections() {
    let Some(speaker) = holder(Duration::from_millis(500)).await else {
        return;
    };
    let port = speaker.addr.port();
    let eight = hex_seeds(&[b"s0", b"s1", b"s2", b"s3", b"s4", b"s5", b"s6", b"s7"]);
    let client = Arc::new(CountingClient::live());
    let profile = profile_for("127.0.0.1", port, Some("raw"), 10, &eight);
    let (lane, job, found) = discover_with(
        Some(common::wildcard_guard(&[port])),
        Arc::clone(&client),
        profile,
        "22conc",
    )
    .await;
    let discovery = found.expect("eight seeds over a scoped loopback endpoint");
    assert_eq!(discovery.points.len(), 8, "eight seeds are eight points");

    let hosts: Vec<Box<dyn aitm_scan_model::ProbeHost>> = discovery
        .points
        .iter()
        .map(|point| {
            lane.probe_host_for(point, Arc::clone(&job))
                .expect("the lane hosts every point it discovered")
        })
        .collect();
    let probes = hosts.iter().map(|host| {
        let case = payload(b"concurrent");
        async move { host.probe(&case).await.map(|_| ()) }
    });
    for result in futures::future::join_all(probes).await {
        result.expect("every authorised probe reaches the speaker");
    }
    assert_eq!(speaker.accepts(), 8, "eight probes are eight connections");
    assert_eq!(
        speaker.max_concurrent(),
        u32::try_from(MAX_CONNECTIONS).expect("four fits"),
        "the job's connection ceiling is {MAX_CONNECTIONS}"
    );
}

/// (4) Message size: a seed over the message ceiling contributes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn ceiling_message_size() {
    let oversize = "00".repeat(70_000);
    assert!(
        oversize.len() / 2 > MAX_MESSAGE,
        "the seed is over the {MAX_MESSAGE}-byte ceiling"
    );
    let client = Arc::new(CountingClient::dry_run());
    let profile = profile_for("127.0.0.1", 9000, Some("raw"), 10, &[oversize]);
    let (_lane, _job, found) = discover_with(
        Some(common::wildcard_guard(&[9000])),
        Arc::clone(&client),
        profile,
        "22big",
    )
    .await;
    let discovery = found.expect("an over-long seed is skipped, not a discovery failure");
    assert_eq!(discovery.nodes.len(), 1, "the endpoint is still a node");
    assert!(
        discovery.points.is_empty(),
        "an over-long seed yields no point: {:?}",
        discovery
            .points
            .iter()
            .map(|point| point.path.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(client.count(), 0, "discovery opens no exchange");
}

// ---------------------------------------------------------------------------
// C16: ids are stable, repeat elements are capped
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn ids_stable_and_capped() {
    let seeds = hex_seeds(&[b"aaa", b"bbb"]);

    // Two independent runs of the same discovery, under different jobs and
    // markers: the ids an operator sees must not move.
    let mut ids: Vec<(Vec<String>, Vec<String>)> = Vec::new();
    for job_id in ["22ida", "22idb"] {
        let profile = profile_for("127.0.0.1", 9000, Some("raw"), 10, &seeds);
        let (_lane, _job, found) = discover_with(
            Some(common::wildcard_guard(&[9000])),
            Arc::new(CountingClient::dry_run()),
            profile,
            job_id,
        )
        .await;
        let discovery = found.expect("two `raw` seeds over a scoped endpoint");
        ids.push((
            discovery
                .points
                .iter()
                .map(|point| point.id.clone())
                .collect(),
            discovery.nodes.iter().map(|node| node.id.clone()).collect(),
        ));
    }
    let (first_points, first_nodes) = &ids[0];
    let (second_points, second_nodes) = &ids[1];
    assert_eq!(first_points.len(), 2, "{first_points:?}");
    assert_eq!(first_points, second_points, "point ids are stable");
    assert_eq!(first_nodes, second_nodes, "node ids are stable");
    assert_eq!(
        first_nodes,
        &vec!["l4s-tcp-127.0.0.1-9000".to_string()],
        "the node id is the endpoint"
    );

    // A RESP array of ten elements yields points for the first four only: the
    // later ones are reached by the structure-aware mutators, not by a point
    // each (spec S5.2 step 4).
    let mut resp: Vec<u8> = b"*10\r\n".to_vec();
    for _ in 0..10 {
        resp.extend_from_slice(b"$1\r\na\r\n");
    }
    let profile = profile_for("127.0.0.1", 9000, Some("resp"), 10, &hex_seeds(&[&resp]));
    let (_lane, _job, found) = discover_with(
        Some(common::wildcard_guard(&[9000])),
        Arc::new(CountingClient::dry_run()),
        profile,
        "22resp",
    )
    .await;
    let discovery = found.expect("a RESP seed over a scoped endpoint");
    let paths: Vec<String> = discovery
        .points
        .iter()
        .map(|point| point.path.clone().unwrap_or_default())
        .collect();
    assert!(
        paths.iter().any(|path| path.starts_with("args[3]")),
        "the last kept element has points: {paths:?}"
    );
    for index in 0..10usize {
        let has = paths
            .iter()
            .any(|path| path.starts_with(&format!("args[{index}]")));
        assert_eq!(
            has,
            index <= MAX_REPEAT_INDEX,
            "args[{index}] in {paths:?} (cap {MAX_REPEAT_INDEX})"
        );
    }
}

// ---------------------------------------------------------------------------
// C18: the core's own listener ports
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn self_port_exclusion() {
    let (speaker, port) = holder_or_unbound(Duration::ZERO).await;
    let seeds = hex_seeds(&[b"abc"]);
    let text = format!("{port} is one of the core's own listener ports");

    // Declared before discovery: the endpoint is never discovered at all.
    let guard = common::wildcard_guard(&[port]);
    guard.set_self_ports([port]);
    let client = Arc::new(CountingClient::live());
    let profile = profile_for("127.0.0.1", port, Some("raw"), 10, &seeds);
    let (_lane, _job, found) = discover_with(
        Some(Arc::clone(&guard)),
        Arc::clone(&client),
        profile,
        "22selfa",
    )
    .await;
    let error = found.expect_err("the lane never addresses the core's own listener");
    assert_eq!(
        error.to_string(),
        format!("scan: out_of_scope: 127.0.0.1:{text}")
    );
    assert_eq!(client.count(), 0, "a refused endpoint opens no exchange");
    accepts_is(speaker.as_ref(), 0, "a refused endpoint opens no socket");

    // Declared *after* discovery, as a new core listener binds mid-job: the
    // next probe is refused by the host's own re-check (A1).
    let guard = common::wildcard_guard(&[port]);
    let client = Arc::new(CountingClient::live());
    let profile = profile_for("127.0.0.1", port, Some("raw"), 10, &seeds);
    let (lane, job, found) = discover_with(
        Some(Arc::clone(&guard)),
        Arc::clone(&client),
        profile,
        "22selfb",
    )
    .await;
    let discovery = found.expect("discovery before the listener bound");
    let point = &discovery.points[0];
    let host = lane
        .probe_host_for(point, Arc::clone(&job))
        .expect("the lane hosts the point");

    guard.add_self_ports([port]);
    let error = host
        .probe(&payload(b"abc"))
        .await
        .expect_err("a probe at the core's own listener is refused");
    assert!(
        matches!(error.downcast_ref::<HostError>(), Some(HostError::Guard(_))),
        "{error}"
    );
    assert!(error.to_string().contains(&text), "{error}");
    assert_eq!(client.count(), 0, "the refused probe opened no exchange");
    accepts_is(speaker.as_ref(), 0, "the refused probe opened no socket");

    // The same port number on a routable address the operator scoped is not the
    // core's own listener: the probe reaches the client, which opens nothing.
    let routable = guard_over(vec![entry(
        Ipv4Addr::new(10, 0, 0, 0),
        8,
        ANY_INTERFACE,
        L4Capability::Inject,
    )]);
    routable.set_self_ports([port]);
    let client = Arc::new(CountingClient::dry_run());
    let profile = profile_for("10.0.0.9", port, Some("raw"), 10, &seeds);
    let (lane, job, found) =
        discover_with(Some(routable), Arc::clone(&client), profile, "22selfc").await;
    let discovery = found.expect("a scoped routable destination on the same port number");
    let point = &discovery.points[0];
    let host = lane
        .probe_host_for(point, Arc::clone(&job))
        .expect("the lane hosts the point");
    let error = host
        .probe(&payload(b"abc"))
        .await
        .expect_err("the client double opens nothing");
    assert_eq!(
        error.downcast_ref::<HostError>(),
        Some(&HostError::DryRun),
        "{error}"
    );
    assert_eq!(client.count(), 1, "the probe reached the client");
    accepts_is(speaker.as_ref(), 0, "and never the loopback speaker");
}

// ---------------------------------------------------------------------------
// C14 / C16: what the discovery line reports
// ---------------------------------------------------------------------------

/// The one `l4_stream discover` line per endpoint carries the counts C14 and
/// C16 are read off (`seeds_dropped_credential`, `points`, `points_dropped`)
/// and still not one byte of a seed (C11).
///
/// Three RESP seeds carry a credential and one does not, so the line must say
/// `seeds_dropped_credential=3` and the surviving points must all come from
/// the fourth.
#[tokio::test]
async fn discovery_line_reports_its_counts() {
    let capture = common::capture_tracing().await;
    let lines = &capture.lines;

    let seeds = hex_seeds(&[
        b"*2\r\n$4\r\nAUTH\r\n$3\r\nabc\r\n",
        b"*3\r\n$4\r\nAUTH\r\n$1\r\nu\r\n$1\r\np\r\n",
        b"*2\r\n$4\r\nauth\r\n$6\r\nsecret\r\n",
        b"*2\r\n$4\r\nECHO\r\n$5\r\nhello\r\n",
    ]);
    // Port 9007 is this test's alone: the capture sink is global and the
    // other tests in this binary run beside it, so the line is picked by the
    // node id rather than by being the first discovery line recorded.
    let profile = profile_for("127.0.0.1", 9007, Some("resp"), 10, &seeds);
    let (_lane, _job, found) = discover_with(
        Some(common::wildcard_guard(&[9007])),
        Arc::new(CountingClient::dry_run()),
        profile,
        "22log",
    )
    .await;
    let discovery = found.expect("one seed survives the credential filter");

    let recorded = lines.lock().expect("the capture sink").clone();
    assert!(
        !recorded.is_empty(),
        "the capture recorded nothing at all, so nothing below is proven"
    );
    let mine: Vec<&String> = recorded
        .iter()
        .filter(|line| {
            line.contains("l4_stream discover") && line.contains("node=l4s-tcp-127.0.0.1-9007")
        })
        .collect();
    assert_eq!(
        mine.len(),
        1,
        "exactly one discovery line per endpoint: {mine:?}"
    );
    let line = mine[0];

    assert!(
        line.contains("seeds_dropped_credential=3"),
        "the line does not count the three AUTH seeds: {line}"
    );
    assert!(line.contains("grammar=resp"), "{line}");
    assert!(line.contains("seeds=1"), "{line}");
    assert!(
        line.contains(&format!("points={}", discovery.points.len())),
        "the line's point count is the discovery's: {line}"
    );
    assert!(
        line.contains("points_dropped=0"),
        "one seed is far under the 256-point cap: {line}"
    );

    // C11 again, on this line: counts only, never a seed byte and never its
    // hex. `secret` is the password in the third seed.
    for line in &recorded {
        assert!(
            !line.contains("secret"),
            "a seed byte reached a log: {line}"
        );
        assert!(
            !line.contains(&encode_hex(b"secret")),
            "a seed's hex reached a log: {line}"
        );
        assert!(!line.contains("ECHO"), "a seed byte reached a log: {line}");
    }

    // And the surviving points are the ECHO seed's.
    assert!(
        !discovery.points.is_empty(),
        "the benign seed yields points"
    );
    for point in &discovery.points {
        let example = point.example.clone().unwrap_or_default();
        assert!(
            !example.contains(&encode_hex(b"secret")),
            "a point example carries a credential: {example}"
        );
    }
}

// ---------------------------------------------------------------------------
// SPEC-I2 / QUAL-I2: a skipped profile seed is reported, not dropped
// ---------------------------------------------------------------------------

/// A seed the corpus could not use is counted on the discovery line and named
/// in the verdict, so an operator who wrote one learns why nothing came of it.
///
/// `flow:` seeds are the case that bites: the HTTP lanes take them, this lane
/// seeds from captured **L4** packets, and until now the note explaining that
/// was computed and thrown away.
#[tokio::test]
async fn a_skipped_profile_seed_is_counted_and_named() {
    use aitm_core::FlowId;
    use aitm_scan_model::FlowRef;

    let capture = common::capture_tracing().await;
    let lines = &capture.lines;

    // Port 9008 is this test's alone: the capture sink is global and the
    // other tests in this binary run beside it.
    let mut profile = profile_for(
        "127.0.0.1",
        9008,
        Some("raw"),
        10,
        &hex_seeds(&[b"\x00\xff"]),
    );
    profile.l4.seeds.insert(
        0,
        L4Seed::Flow {
            flow: FlowRef(FlowId::new()),
        },
    );

    let target = profile.target.clone();
    let client = Arc::new(CountingClient::dry_run());
    let lane = lane_with_client(
        Some(common::wildcard_guard(&[9008])),
        None,
        Arc::clone(&client) as Arc<dyn StreamClient>,
    );
    // The deadline has already passed, so the campaign stops at its baseline
    // and the verdict is the S6.5 detail line and nothing else.
    let job: Arc<dyn JobCtx> = Arc::new(
        TestJob::new(profile)
            .with_job_id("22seed")
            .with_marker("aitm22seed")
            .with_deadline(Instant::now() - Duration::from_secs(1)),
    );
    let discovery = lane
        .discover(&target, job.as_ref())
        .await
        .expect("an unusable seed is skipped, not a discovery failure");
    assert_eq!(
        discovery.points.len(),
        1,
        "the one usable seed is still a point"
    );

    let recorded = lines.lock().expect("the capture sink").clone();
    assert!(
        !recorded.is_empty(),
        "the capture recorded nothing at all, so nothing below is proven"
    );
    let mine: Vec<&String> = recorded
        .iter()
        .filter(|line| {
            line.contains("l4_stream discover") && line.contains("node=l4s-tcp-127.0.0.1-9008")
        })
        .collect();
    assert_eq!(mine.len(), 1, "one discovery line per endpoint: {mine:?}");
    assert!(
        mine[0].contains("seeds_skipped=1"),
        "the discovery line does not count the skipped seed: {}",
        mine[0]
    );

    let point = &discovery.points[0];
    let host = lane
        .probe_host_for(point, Arc::clone(&job))
        .expect("the lane hosts the point");
    let verdict = check_by_id(&lane.checks(), "l4-crash")
        .run(point, host.as_ref())
        .await;

    assert!(
        verdict.detail.contains("flow seeds are not L4 flows"),
        "the verdict does not say why the seed was skipped: {}",
        verdict.detail
    );
    assert!(
        verdict.detail.contains("seed_notes=["),
        "the notes are not in the S6.5 detail line: {}",
        verdict.detail
    );
    assert_eq!(client.count(), 0, "a passed deadline opens no exchange");
}

/// The profile's seeds are the same for every endpoint, so they are decoded
/// once and the skipped-seed notes are shared, not recomputed per endpoint.
///
/// One `flow:` seed this lane cannot use, two L4 endpoints: each endpoint's
/// discovery line counts the one skipped seed, and each endpoint's verdict
/// carries the very same note — once.
#[tokio::test]
async fn one_profile_seed_is_decoded_once_for_every_endpoint() {
    use aitm_core::FlowId;
    use aitm_scan_model::FlowRef;

    let capture = common::capture_tracing().await;
    let lines = &capture.lines;

    // Ports 9013 and 9014 are this test's alone: the capture sink is global.
    let mut profile = profile_for(
        "127.0.0.1",
        9013,
        Some("raw"),
        10,
        &hex_seeds(&[b"\x00\xff"]),
    );
    profile.l4.seeds.insert(
        0,
        L4Seed::Flow {
            flow: FlowRef(FlowId::new()),
        },
    );
    profile.target.l4.push(L4TargetSpec {
        ip: "127.0.0.1".to_string(),
        port: 9014,
        proto: L4Transport::Tcp,
        grammar: Some("raw".to_string()),
    });

    let target = profile.target.clone();
    let client = Arc::new(CountingClient::dry_run());
    let lane = lane_with_client(
        Some(common::wildcard_guard(&[9013, 9014])),
        None,
        Arc::clone(&client) as Arc<dyn StreamClient>,
    );
    let job: Arc<dyn JobCtx> = Arc::new(
        TestJob::new(profile)
            .with_job_id("22two")
            .with_marker("aitm22two")
            .with_deadline(Instant::now() - Duration::from_secs(1)),
    );
    let discovery = lane
        .discover(&target, job.as_ref())
        .await
        .expect("two endpoints, each with one usable seed");
    assert_eq!(
        discovery.points.len(),
        2,
        "one usable seed per endpoint is one point each"
    );

    // Each endpoint's discovery line counts the one skipped seed.
    let recorded = lines.lock().expect("the capture sink").clone();
    assert!(
        !recorded.is_empty(),
        "the capture recorded nothing at all, so nothing below is proven"
    );
    for port in ["9013", "9014"] {
        let mine: Vec<&String> = recorded
            .iter()
            .filter(|line| {
                line.contains("l4_stream discover")
                    && line.contains(&format!("node=l4s-tcp-127.0.0.1-{port}"))
            })
            .collect();
        assert_eq!(mine.len(), 1, "one discovery line for {port}: {mine:?}");
        assert!(
            mine[0].contains("seeds_skipped=1"),
            "the discovery line for {port} does not count the skipped seed: {}",
            mine[0]
        );
    }

    // The note rides each endpoint's verdict, once, and it is the same note:
    // the shared, decode-once list.
    let clause = |detail: &str| -> String {
        let start = detail
            .find("seed_notes=[")
            .expect("the verdict carries a seed_notes clause");
        let rest = &detail[start..];
        // The clause is the detail's last, and a note may itself hold a `]`
        // (`seed[0]: ...`), so the closing bracket is the final one.
        let end = rest.rfind(']').expect("the seed_notes clause closes");
        rest[..=end].to_string()
    };
    let mut clauses = Vec::new();
    for point in &discovery.points {
        let host = lane
            .probe_host_for(point, Arc::clone(&job))
            .expect("the lane hosts the point");
        let verdict = check_by_id(&lane.checks(), "l4-crash")
            .run(point, host.as_ref())
            .await;
        assert_eq!(
            verdict.detail.matches("seed_notes=[").count(),
            1,
            "the note rides the verdict exactly once: {}",
            verdict.detail
        );
        clauses.push(clause(&verdict.detail));
    }
    assert_eq!(clauses.len(), 2);
    assert_eq!(
        clauses[0], clauses[1],
        "both endpoints carry the same single note"
    );
    assert!(
        clauses[0].contains("flow seeds are not L4 flows"),
        "the shared note names the reason: {}",
        clauses[0]
    );
}

// ---------------------------------------------------------------------------
// SPEC-I3 / S9: a refusal and a dead target are warned about
// ---------------------------------------------------------------------------

/// Discovery's own S5.2 step-1 preview, refused, is a WARN an operator sees
/// without turning on debug logging: the endpoint is named, with the reason
/// and nothing else — no byte of a case or a reply (spec S9, SPEC-I3, C11).
///
/// Both halves of S5.1's refusal go through `authorise_preview`, the one
/// refusal point: an endpoint outside the operator's L4 scope, and a lane
/// whose L4 subsystem is disabled.
#[tokio::test]
async fn a_refused_preview_is_warned() {
    let seeds = hex_seeds(&[b"abc"]);
    let capture = common::capture_tracing().await;
    let lines = &capture.lines;

    // (a) An endpoint not in the operator's L4 scope at all.
    let client = Arc::new(CountingClient::live());
    let profile = profile_for("127.0.0.1", 9011, Some("raw"), 10, &seeds);
    let (_lane, _job, found) = discover_with(
        Some(guard_over(vec![entry(
            Ipv4Addr::new(10, 0, 0, 0),
            8,
            ANY_INTERFACE,
            L4Capability::Inject,
        )])),
        Arc::clone(&client),
        profile,
        "22prev",
    )
    .await;
    let error = found.expect_err("an unscoped endpoint is never discovered");
    assert!(
        error.to_string().starts_with("scan: out_of_scope: "),
        "{error}"
    );
    assert_eq!(client.count(), 0, "a refusal opens no exchange");

    // (b) S5.1: a disabled lane refuses the same preview, named and warned
    // through the very same path — not an early return the operator never
    // sees.
    let off_client = Arc::new(CountingClient::live());
    let profile = profile_for("127.0.0.1", 9012, Some("raw"), 10, &seeds);
    let (_lane, _job, found) = discover_with(None, Arc::clone(&off_client), profile, "22off").await;
    let error = found.expect_err("a disabled lane discovers nothing");
    assert!(
        error.to_string().starts_with("scan: refused_l4: "),
        "{error}"
    );
    assert_eq!(off_client.count(), 0, "a refusal opens no exchange");

    let recorded = lines.lock().expect("the capture sink").clone();
    assert!(
        !recorded.is_empty(),
        "the capture recorded nothing at all, so nothing below is proven"
    );
    let scope_warn: Vec<&String> = recorded
        .iter()
        .filter(|line| line.starts_with("WARN ") && line.contains("endpoint=127.0.0.1:9011"))
        .collect();
    assert_eq!(
        scope_warn.len(),
        1,
        "one WARN for the out-of-scope preview: {recorded:?}"
    );
    assert!(scope_warn[0].contains("out_of_scope"), "{}", scope_warn[0]);
    let off_warn: Vec<&String> = recorded
        .iter()
        .filter(|line| line.starts_with("WARN ") && line.contains("endpoint=127.0.0.1:9012"))
        .collect();
    assert_eq!(
        off_warn.len(),
        1,
        "one WARN for the disabled-lane preview: {recorded:?}"
    );
    assert!(off_warn[0].contains("refused_l4"), "{}", off_warn[0]);
}

/// The A1 self-port re-check refuses after discovery and opens no socket, and
/// that refusal is a WARN naming the point and the endpoint (spec S9, C11).
#[tokio::test]
async fn a_guard_refusal_is_warned() {
    let seeds = hex_seeds(&[b"abc"]);
    let capture = common::capture_tracing().await;
    let lines = &capture.lines;
    let guard = common::wildcard_guard(&[9009]);
    let client = Arc::new(CountingClient::live());
    let profile = profile_for("127.0.0.1", 9009, Some("raw"), 10, &seeds);
    let (lane, job, found) = discover_with(
        Some(Arc::clone(&guard)),
        Arc::clone(&client),
        profile,
        "22warn",
    )
    .await;
    let discovery = found.expect("discovery before the listener bound");
    let point = &discovery.points[0];
    let host = lane
        .probe_host_for(point, Arc::clone(&job))
        .expect("the lane hosts the point");
    guard.add_self_ports([9009]);
    let error = host
        .probe(&payload(b"abc"))
        .await
        .expect_err("the lane never probes the core's own listener");
    assert!(
        matches!(error.downcast_ref::<HostError>(), Some(HostError::Guard(_))),
        "{error}"
    );
    assert_eq!(client.count(), 0, "a refusal opens no exchange");

    let recorded = lines.lock().expect("the capture sink").clone();
    assert!(
        !recorded.is_empty(),
        "the capture recorded nothing at all, so nothing below is proven"
    );
    // Ports 9009 and 9010 are this test's alone: the capture sink is global
    // and the other tests in this binary emit into it beside us, so a line is
    // picked by the point it names and not by being the only one of its kind.
    let warned: Vec<&String> = recorded
        .iter()
        .filter(|line| {
            line.starts_with("WARN ")
                && line.contains("listener ports")
                && line.contains(point.id.as_str())
        })
        .collect();
    assert_eq!(
        warned.len(),
        1,
        "one WARN for the guard refusal: {recorded:?}"
    );
    assert!(
        warned[0].contains("endpoint=127.0.0.1:9009"),
        "{}",
        warned[0]
    );
}

/// A target that is not there at all: the campaign's first connect is
/// refused, so it stops `target_down`, and that is a WARN naming the point —
/// not a DEBUG line an operator has to go looking for (spec S9, SPEC-I3).
#[tokio::test]
async fn a_target_that_never_recovers_is_warned() {
    // An ephemeral loopback port, bound only to learn a free number and then
    // dropped, so nothing listens on it and the connect is refused. Binding
    // is the sandbox's call, so skip when it refuses.
    let Some(listener) = common::bind_or_skip().await else {
        return;
    };
    let port = listener
        .local_addr()
        .expect("the ephemeral listener has an address")
        .port();
    drop(listener);

    let seeds = hex_seeds(&[b"abc"]);
    let capture = common::capture_tracing().await;
    let lines = &capture.lines;
    let client = Arc::new(CountingClient::live());
    let profile = profile_for("127.0.0.1", port, Some("raw"), 10, &seeds);
    let (lane, job, found) = discover_with(
        Some(common::wildcard_guard(&[port])),
        Arc::clone(&client),
        profile,
        "22down",
    )
    .await;
    let discovery = found.expect("discovery opens no socket, so it succeeds");
    let point = &discovery.points[0];
    let host = lane
        .probe_host_for(point, Arc::clone(&job))
        .expect("the lane hosts the point");
    let verdict = check_by_id(&lane.checks(), "l4-crash")
        .run(point, host.as_ref())
        .await;
    assert!(
        verdict.detail.contains("stop=target_down"),
        "a target that never answers stops the campaign: {}",
        verdict.detail
    );

    let recorded = lines.lock().expect("the capture sink").clone();
    let warned: Vec<&String> = recorded
        .iter()
        .filter(|line| {
            line.starts_with("WARN ")
                && line.contains("target")
                && line.contains("recover")
                && line.contains(point.id.as_str())
        })
        .collect();
    assert_eq!(
        warned.len(),
        1,
        "one WARN for the target that never came back: {recorded:?}"
    );
    assert!(warned[0].contains("job=22down"), "{}", warned[0]);
}
