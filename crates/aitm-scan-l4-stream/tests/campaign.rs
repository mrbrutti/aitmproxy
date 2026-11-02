//! Inner loop only: in-process speakers; not acceptance evidence for T6-1..T6-5.
//!
//! Child criteria **C7** (the campaign state machine) and **C11** (no message
//! byte in a log line or a `Debug`), driven the way the engine drives the lane:
//! `discover`, then one `probe_host_for` per check, then `Check::run`. The
//! speakers in [`common`] mimic T10's D5 triggers in this process; only Task 23's
//! real run against T10's speakers satisfies T6-1..T6-5.
//!
//! Every test binds an ephemeral loopback port. A sandbox that refuses local
//! binding makes [`common::bind_or_skip`] print `SKIP: sandbox refuses local
//! binding` and the test return; where a port *can* be bound the test asserts
//! and fails loudly. The reproduction spacing (1 s x 3) and the recovery polls
//! are real time, so a test here takes 10-30 s.

mod common;

use std::sync::atomic::Ordering;
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use aitm_scan_l4_stream::checks::{self, Campaign};
use aitm_scan_l4_stream::client::testing::CountingClient;
use aitm_scan_l4_stream::client::StreamClient;
use aitm_scan_l4_stream::codec::encode_hex;
use aitm_scan_l4_stream::host::{HostError, StreamHost};
use aitm_scan_l4_stream::lane_with_client;
use aitm_scan_l4_stream::mutate::schedule::Schedule;
use aitm_scan_l4_stream::state::JobState;
use aitm_scan_l4_stream::tree::FieldPath;
use aitm_scan_model::{
    builtin_profiles, Check, Confidence, InsertionPoint, JobCtx, L4Seed, L4TargetSpec, L4Transport,
    Lane, Outcome, Payload, PayloadMode, ProfileTarget, ScanProfile, Verdict,
};

use common::{Speaker, TestJob};

/// The ASCII marker C11 forbids in every log line and every `Debug`.
const SECRET: &[u8] = b"S3CR3TBYTES";

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

/// `l4-stream-safe` with the case budget, the seeds and the timeout ceiling a
/// test needs, over one loopback endpoint.
fn profile_for(port: u16, grammar: Option<&str>, cases: u32, seeds: &[&str]) -> ScanProfile {
    let mut profile = safe_profile();
    profile.l4.cases = cases;
    profile.l4.seeds = seeds
        .iter()
        .map(|hex| L4Seed::Hex {
            hex: (*hex).to_string(),
        })
        .collect();
    profile.target = target_for(port, grammar);
    profile
}

/// One L4 endpoint on loopback.
fn target_for(port: u16, grammar: Option<&str>) -> ProfileTarget {
    ProfileTarget {
        origins: Vec::new(),
        l4: vec![L4TargetSpec {
            ip: "127.0.0.1".to_string(),
            port,
            proto: L4Transport::Tcp,
            grammar: grammar.map(str::to_string),
        }],
    }
}

/// The discovered point at `path`, which is the one the test fuzzes.
fn point_at(points: &[InsertionPoint], path: &str) -> InsertionPoint {
    points
        .iter()
        .find(|point| point.path.as_deref() == Some(path))
        .unwrap_or_else(|| {
            panic!(
                "discovery produced no point at `{path}`; it produced {:?}",
                points
                    .iter()
                    .map(|point| point.path.clone())
                    .collect::<Vec<_>>()
            )
        })
        .clone()
}

/// The lane's check with this catalogue id.
fn check_by_id(checks: &[Arc<dyn Check>], id: &str) -> Arc<dyn Check> {
    checks
        .iter()
        .find(|check| check.meta().id == id)
        .unwrap_or_else(|| panic!("the lane ships a `{id}` check"))
        .clone()
}

/// A payload carrying `bytes` at the point.
fn payload(bytes: &[u8]) -> Payload {
    Payload {
        value: String::new(),
        mode: PayloadMode::Replace,
        bytes: Some(bytes.to_vec()),
    }
}

/// The whole lane under one speaker: the guard, the counting client, the job
/// and the discovered points.
struct Run {
    lane: Arc<aitm_scan_l4_stream::L4StreamLane>,
    client: Arc<CountingClient>,
    job: Arc<dyn JobCtx>,
    job_id: String,
    points: Vec<InsertionPoint>,
    checks: Vec<Arc<dyn Check>>,
}

impl Run {
    /// Discover against `speaker` under `profile`, as the engine would.
    async fn start(speaker: &Speaker, profile: ScanProfile, job_id: &str) -> Run {
        let guard = common::wildcard_guard(&[speaker.addr.port()]);
        let client = Arc::new(CountingClient::live());
        let target = profile.target.clone();
        let lane = lane_with_client(
            Some(guard),
            None,
            Arc::clone(&client) as Arc<dyn StreamClient>,
        );
        let job: Arc<dyn JobCtx> = Arc::new(
            TestJob::new(profile)
                .with_job_id(job_id)
                .with_marker(&format!("aitm{job_id}")),
        );
        let discovery = lane
            .discover(&target, job.as_ref())
            .await
            .expect("discovery over a scoped loopback endpoint succeeds");
        let checks = lane.checks();
        Run {
            lane,
            client,
            job,
            job_id: job_id.to_string(),
            points: discovery.points,
            checks,
        }
    }

    /// Run one check against `point`, through its own host, as the engine does.
    async fn run_check(&self, id: &str, point: &InsertionPoint) -> Verdict {
        let host = self
            .lane
            .probe_host_for(point, Arc::clone(&self.job))
            .expect("the lane hosts probes for a point it discovered");
        check_by_id(&self.checks, id)
            .run(point, host.as_ref())
            .await
    }

    /// The job's lane state.
    fn state(&self) -> Arc<JobState> {
        self.lane
            .state()
            .get(&self.job_id)
            .expect("discovery left state for the job")
    }
}

/// `JobState`'s mutex, read without caring about a poisoned lock.
fn locked<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// The harness itself
// ---------------------------------------------------------------------------

/// The speakers' trigger rules, over an in-memory pipe.
///
/// Not part of C7: it guards the harness the C7 tests rest on, and it is the
/// one test here that still asserts where the sandbox refuses to bind, so a
/// speaker that stops mimicking T10's D5 triggers is caught before the
/// Terminal run.
#[tokio::test(flavor = "multi_thread")]
async fn speakers_mimic_t10_triggers() {
    use tokio::io::AsyncWriteExt;

    let counters = common::Counters::new();

    // A whole frame: two big-endian length bytes, then that many.
    let (mut ours, mut theirs) = tokio::io::duplex(256);
    theirs
        .write_all(&[0x00, 0x03, b'a', b'b', b'c'])
        .await
        .expect("the pipe takes a frame");
    assert_eq!(
        common::tlv_read(&mut ours, &counters).await,
        common::TlvRead::Frame(vec![0x00, 0x03, b'a', b'b', b'c'])
    );

    // A declared length over 4096 is a trigger on its own: at once, without
    // waiting out the idle window.
    let (mut ours, mut theirs) = tokio::io::duplex(256);
    theirs
        .write_all(&[0xff, 0xff, b'a'])
        .await
        .expect("the pipe takes a header");
    let started = std::time::Instant::now();
    assert_eq!(
        common::tlv_read(&mut ours, &counters).await,
        common::TlvRead::Trigger
    );
    assert!(
        started.elapsed() < common::IDLE,
        "an over-long declared length waited {:?} instead of triggering at once",
        started.elapsed()
    );

    // A declared length over what arrived is a trigger after 200 ms idle.
    let (mut ours, mut theirs) = tokio::io::duplex(256);
    theirs
        .write_all(&[0x00, 0x04, b'a', b'b', b'c'])
        .await
        .expect("the pipe takes a short frame");
    let started = std::time::Instant::now();
    assert_eq!(
        common::tlv_read(&mut ours, &counters).await,
        common::TlvRead::Trigger
    );
    assert!(
        started.elapsed() >= common::IDLE,
        "the idle rule waited {:?}",
        started.elapsed()
    );

    // A peer that goes away is not a trigger.
    let (mut ours, theirs) = tokio::io::duplex(256);
    drop(theirs);
    assert_eq!(
        common::tlv_read(&mut ours, &counters).await,
        common::TlvRead::Gone
    );

    // Every decision is logged, bytes and all: the speaker's own record.
    assert_eq!(counters.messages().len(), 3);

    // RESP: only a bulk length over 1 MiB is a trigger.
    assert!(common::oversize_bulk(b"*1\r\n$2147483647\r\nPING\r\n"));
    assert!(!common::oversize_bulk(b"*1\r\n$4\r\nPING\r\n"));
    assert!(!common::oversize_bulk(b"*1\r\n$1048576\r\nPING\r\n"));
    assert!(!common::oversize_bulk(b"PING\r\n"));

    // One message is whatever arrives, drained.
    let (mut ours, mut theirs) = tokio::io::duplex(256);
    theirs
        .write_all(b"PING\r\n")
        .await
        .expect("the pipe takes a line");
    assert_eq!(
        common::read_message(&mut ours).await,
        Some(b"PING\r\n".to_vec())
    );
}

// ---------------------------------------------------------------------------
// C7: the campaign state machine
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn crash_is_reproduced_and_retired() {
    let Some(speaker) = common::tlv_crash(Duration::from_secs(1)).await else {
        return;
    };
    let profile = profile_for(speaker.addr.port(), None, 50, &["0003616263", "0001ff"]);
    let run = Run::start(&speaker, profile, "scan-21-crash").await;
    let point = point_at(&run.points, "length");

    let crash = run.run_check("l4-crash", &point).await;
    assert_eq!(crash.outcome, Outcome::Vulnerable, "{}", crash.detail);
    assert_eq!(crash.confidence, Confidence::Firm, "{}", crash.detail);
    let l4 = crash
        .evidence
        .l4
        .as_ref()
        .expect("a crash verdict carries its L4 evidence");
    assert_eq!(l4.reproduced, (3, 3), "{}", crash.detail);
    assert!(l4.liveness_before, "{l4:?}");
    assert!(!l4.liveness_after, "{l4:?}");
    assert!(
        l4.mutation_chain
            .first()
            .is_some_and(|first| first.starts_with("len_desync(")),
        "{:?}",
        l4.mutation_chain
    );
    assert!(
        run.state().is_retired(&point.id),
        "the crashing point is retired"
    );

    // A further probe on a retired point sends nothing.
    let host = run
        .lane
        .probe_host_for(&point, Arc::clone(&run.job))
        .expect("the lane still hosts the retired point");
    let error = host
        .probe(&payload(b"\x00\x03abc"))
        .await
        .expect_err("a retired point refuses every probe");
    assert_eq!(
        error.downcast_ref::<HostError>(),
        Some(&HostError::Retired),
        "{error}"
    );

    // The parser-fault check reads the stored campaign: no further traffic.
    let accepts_before = speaker.accepts();
    let exchanges_before = run.client.exchanges.load(Ordering::SeqCst);
    let parser_fault = run.run_check("l4-parser-fault", &point).await;
    assert_eq!(
        parser_fault.outcome,
        Outcome::Clean,
        "{}",
        parser_fault.detail
    );
    assert_eq!(speaker.accepts(), accepts_before, "the speaker saw no more");
    assert_eq!(
        run.client.exchanges.load(Ordering::SeqCst),
        exchanges_before,
        "the client opened no further exchange"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn silent_close_is_parser_fault() {
    let Some(speaker) = common::tlv_close_silent().await else {
        return;
    };
    let profile = profile_for(speaker.addr.port(), None, 50, &["0003616263", "0001ff"]);
    let run = Run::start(&speaker, profile, "scan-21-silentclose").await;
    let point = point_at(&run.points, "length");

    let fault = run.run_check("l4-parser-fault", &point).await;
    assert_eq!(fault.outcome, Outcome::Vulnerable, "{}", fault.detail);
    assert_eq!(fault.confidence, Confidence::Firm, "{}", fault.detail);
    let l4 = fault
        .evidence
        .l4
        .as_ref()
        .expect("a parser-fault verdict carries its L4 evidence");
    assert_eq!(l4.reproduced, (3, 3), "{}", fault.detail);

    let crash = run.run_check("l4-crash", &point).await;
    assert_eq!(crash.outcome, Outcome::Clean, "{}", crash.detail);
    assert!(
        !run.state().is_retired(&point.id),
        "a parser fault retires nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn p_mode_is_clean() {
    // TLV: the speaker answers the bad length with `00 03 45 52 52` and closes.
    let Some(tlv) = common::tlv_p_mode().await else {
        return;
    };
    let profile = profile_for(tlv.addr.port(), None, 50, &["0003616263", "0001ff"]);
    let run = Run::start(&tlv, profile, "scan-21-ptlv").await;
    let point = point_at(&run.points, "length");
    for id in ["l4-crash", "l4-parser-fault", "l4-latency-outlier"] {
        let verdict = run.run_check(id, &point).await;
        assert_eq!(verdict.outcome, Outcome::Clean, "{id}: {}", verdict.detail);
        assert!(verdict.evidence.l4.is_none(), "{id}: {verdict:?}");
    }
    assert!(
        tlv.triggered(),
        "the TLV P-mode speaker never saw a bad length: {:?} messages",
        tlv.messages().len()
    );

    // RESP: the speaker answers `$N` over 1 MiB with its own error and closes.
    let Some(resp) = common::resp_p_mode().await else {
        return;
    };
    let profile = profile_for(
        resp.addr.port(),
        Some("resp"),
        50,
        &["2a310d0a24340d0a50494e470d0a"],
    );
    let run = Run::start(&resp, profile, "scan-21-presp").await;
    let point = point_at(&run.points, "args[0].len");
    for id in ["l4-crash", "l4-parser-fault", "l4-latency-outlier"] {
        let verdict = run.run_check(id, &point).await;
        assert_eq!(verdict.outcome, Outcome::Clean, "{id}: {}", verdict.detail);
        assert!(verdict.evidence.l4.is_none(), "{id}: {verdict:?}");
    }
    assert!(
        resp.triggered(),
        "the RESP P-mode speaker never saw a bulk length over 1 MiB"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn latency_outlier() {
    // Under the lane's 2 s `REPLY_TIMEOUT`, so the case is a slow *reply* and
    // not a timeout, and far over five times the speaker's own floor. Spec C7
    // says 2 s, which is exactly the reply timeout: see the handback note.
    const DELAY: Duration = Duration::from_secs(1);

    let Some(speaker) = common::tlv_slow_case(DELAY, Vec::new()).await else {
        return;
    };
    let profile = profile_for(speaker.addr.port(), None, 200, &["0003616263", "0001ff"]);
    let run = Run::start(&speaker, profile, "scan-21-slow").await;
    // The `payload` point, not `length`: a case on the length node leaves the
    // frame incomplete by construction, and since F4 the latency rule does
    // not time such a case at all (`affects_framing`). Every `payload` case
    // is re-rendered with its length satisfied, so the speaker reads a whole
    // frame and the 1 s it then withholds is the processing delay the rule
    // is meant to catch.
    let point = point_at(&run.points, "payload");

    // Discovery opens no socket, so the case the speaker holds back can be
    // named now, from this point's own schedule: late enough in it that the
    // lane has its ten latency samples before the case arrives.
    speaker.set_slow_case(nth_case_bytes(&run, &point, 20));

    let verdict = run.run_check("l4-latency-outlier", &point).await;
    assert!(
        speaker.triggered(),
        "the speaker never saw the case it was told to hold back"
    );
    assert_eq!(verdict.outcome, Outcome::Vulnerable, "{}", verdict.detail);
    assert_eq!(
        verdict.confidence,
        Confidence::Tentative,
        "{}",
        verdict.detail
    );
    let l4 = verdict
        .evidence
        .l4
        .as_ref()
        .expect("a latency verdict carries its L4 evidence");
    assert_eq!(l4.reproduced, (1, 2), "{}", verdict.detail);
    assert!(
        verdict.detail.contains("latency outlier"),
        "{}",
        verdict.detail
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn consecutive_timeouts_stop() {
    let Some(speaker) = common::silent().await else {
        return;
    };
    let mut profile = profile_for(speaker.addr.port(), None, 50, &["0003616263", "0001ff"]);
    profile.l4.consecutive_timeouts = 3;
    let run = Run::start(&speaker, profile, "scan-21-silent").await;
    let point = point_at(&run.points, "length");

    let verdict = run.run_check("l4-crash", &point).await;
    assert_eq!(verdict.outcome, Outcome::Inconclusive, "{}", verdict.detail);
    assert!(
        verdict.detail.contains("consecutive timeouts 3"),
        "{}",
        verdict.detail
    );

    let host = run
        .lane
        .probe_host_for(&point, Arc::clone(&run.job))
        .expect("the lane still hosts the point");
    let error = host
        .probe(&payload(b"\x00\x03abc"))
        .await
        .expect_err("the lane has given up on a target that never answers");
    assert_eq!(
        error.downcast_ref::<HostError>(),
        Some(&HostError::ConsecutiveTimeouts(3)),
        "{error}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn target_never_recovers() {
    let Some(speaker) = common::dead_after_trigger().await else {
        return;
    };
    let capture = common::capture_tracing().await;
    let lines = &capture.lines;
    let profile = profile_for(speaker.addr.port(), None, 50, &["0003616263", "0001ff"]);
    let run = Run::start(&speaker, profile, "scan-21-dead").await;
    let point = point_at(&run.points, "length");

    let verdict = run.run_check("l4-crash", &point).await;
    assert_eq!(verdict.outcome, Outcome::Vulnerable, "{}", verdict.detail);
    assert_eq!(
        verdict.confidence,
        Confidence::Tentative,
        "{}",
        verdict.detail
    );
    let l4 = verdict
        .evidence
        .l4
        .as_ref()
        .expect("a crash verdict carries its L4 evidence");
    assert_eq!(l4.reproduced, (1, 1), "{}", verdict.detail);
    assert!(
        verdict.detail.contains("did not recover"),
        "{}",
        verdict.detail
    );

    // SPEC-I3: a target that stopped answering is a WARN, not a DEBUG line
    // an operator has to go looking for. Ids and counts only (C11).
    let recorded = locked(lines).clone();
    assert!(
        !recorded.is_empty(),
        "the capture recorded nothing, so it proves nothing"
    );
    let warned: Vec<&String> = recorded
        .iter()
        .filter(|line| {
            line.starts_with("WARN ") && line.contains("target") && line.contains("recover")
        })
        .collect();
    assert_eq!(
        warned.len(),
        1,
        "one WARN for the target that never came back: {recorded:?}"
    );
    assert!(
        warned[0].contains(&point.id),
        "the WARN names the point: {}",
        warned[0]
    );
}

// ---------------------------------------------------------------------------
// C11: no message byte in a log line or a `Debug`
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn no_bytes_in_logs_or_debug() {
    let Some(speaker) = common::tlv_crash(Duration::from_secs(1)).await else {
        return;
    };
    let capture = common::capture_tracing().await;
    let lines = &capture.lines;

    // The seed carries the marker: `000b` declares its eleven bytes.
    let secret_seed = format!("000b{}", encode_hex(SECRET));
    let profile = profile_for(speaker.addr.port(), None, 50, &[&secret_seed, "0001ff"]);
    let run = Run::start(&speaker, profile, "scan-21-c11").await;
    let point = point_at(&run.points, "length");
    let crash = run.run_check("l4-crash", &point).await;
    assert_eq!(crash.outcome, Outcome::Vulnerable, "{}", crash.detail);

    let hex = encode_hex(SECRET);
    let marker = String::from_utf8_lossy(SECRET).into_owned();
    let forbidden = [marker, hex.clone(), hex.to_uppercase()];

    let recorded = locked(lines).clone();
    assert!(
        !recorded.is_empty(),
        "the capture recorded nothing, so it proves nothing"
    );
    for line in &recorded {
        for needle in &forbidden {
            assert!(
                !line.contains(needle.as_str()),
                "a log line carries `{needle}`: {line}"
            );
        }
    }

    // `Debug` of the campaign, the host, the lane state and one case.
    let state = run.state();
    let dp = locked(&state.points)
        .get(&point.id)
        .cloned()
        .expect("the point is in the discovery cache");
    let grammar = locked(&state.grammars)
        .get(&dp.node_id)
        .map(Arc::clone)
        .expect("discovery stored the inferred TLV grammar");
    let host = StreamHost::new(
        dp.clone(),
        Arc::clone(&grammar),
        Arc::clone(&run.job),
        run.job.marker(),
        Arc::clone(&state),
        None,
        Arc::clone(&run.client) as Arc<dyn StreamClient>,
    );
    let campaign_host = run
        .lane
        .probe_host_for(&point, Arc::clone(&run.job))
        .expect("the lane hosts the point");
    let campaign: Arc<Campaign> =
        Campaign::run_or_read(&point, campaign_host.as_ref(), run.lane.state())
            .await
            .expect("the campaign ran during the crash check");
    let mut schedule = Schedule::new(
        grammar
            .parse(&dp.seed_bytes)
            .expect("the seed parses under its own inferred grammar"),
        grammar.spec(),
        FieldPath::new(point.path.as_deref().unwrap_or_default()),
        dp.grammar,
        1,
        8,
        Vec::new(),
    );
    let case = schedule.next().expect("the schedule has a first case");

    let rendered = [
        format!("{campaign:?}"),
        format!("{host:?}"),
        format!("{state:?}"),
        format!("{case:?}"),
    ];
    for text in &rendered {
        for needle in &forbidden {
            assert!(
                !text.contains(needle.as_str()),
                "a `Debug` carries `{needle}`: {text}"
            );
        }
    }
}

/// The bytes of the schedule's case at or after `index`, which the slow
/// speaker keys on.
///
/// Rebuilt from exactly the inputs the campaign uses — the same tree, path,
/// grammar, RNG seed, plan size and donor seeds — because spec S6.4's schedule
/// is deterministic, so these are the bytes the campaign will send.
fn nth_case_bytes(run: &Run, point: &InsertionPoint, index: u32) -> Vec<u8> {
    let state = run.state();
    let dp = locked(&state.points)
        .get(&point.id)
        .cloned()
        .expect("the point is in the discovery cache");
    let grammar = locked(&state.grammars)
        .get(&dp.node_id)
        .map(Arc::clone)
        .expect("discovery stored the inferred grammar");
    let tree = grammar
        .parse(&dp.seed_bytes)
        .expect("the seed parses under its own grammar");
    let rng_seed = aitm_scan_l4_stream::codec::fnv1a64(
        format!("{}|{}", run.job.marker(), point.id).as_bytes(),
    );

    // The campaign's own two inputs, not a copy of them: the donor seeds that
    // feed the crossover and splice mutators (a schedule without them
    // diverges after stage one) and the plan size.
    let donors = checks::donors_for(&state, &dp);
    let planned = checks::cases_planned(
        run.job.profile().l4.cases,
        state.points_total.load(Ordering::SeqCst),
        run.job.budget_left(),
    );
    assert!(
        planned > index,
        "a plan of {planned} cases never reaches case #{index}"
    );
    let schedule = Schedule::new(
        tree,
        grammar.spec(),
        FieldPath::new(point.path.as_deref().unwrap_or_default()),
        dp.grammar,
        rng_seed,
        planned,
        donors,
    );
    schedule
        .filter(|case| case.index >= index && !case.bytes.is_empty() && case.bytes.len() <= 64)
        .map(|case| case.bytes)
        .next()
        .expect("the schedule has a short case at or after the index")
}
