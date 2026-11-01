//! The L4 packet lane's real-wire proof — scanner v2 track T5, plan task 12.
//!
//! Everything else in this crate runs against `testing::MockBackend`. These
//! three tests run the real [`PcapBackend`] over the real loopback interface,
//! so the oracle is judged by the kernel rather than by a fixture: a closed UDP
//! port answers ICMP type 3 code 3, a closed TCP port answers RST, and a real
//! UDP echo thread survives exactly 100 cases (spec Verification; AC T5-2a and
//! T5-1 at lane level).
//!
//! # Running it
//!
//! Opening a pcap handle needs raw capture privilege, which no automated
//! session here has, so all three are `#[ignore]`d. The operator runs them from
//! the worktree root in the Terminal panel:
//!
//! ```text
//! AITM_L4_TESTS=1 cargo test -p aitm-scan-l4-packet --test live_loopback \
//!     -- --ignored --nocapture --test-threads=1 2>&1 | tee /tmp/claude/t5-live.log
//! ```
//!
//! Without `AITM_L4_TESTS=1`, or without pcap privilege, each test prints a
//! `SKIP 77` line saying which of the two it was and returns green. This file
//! never changes system state, never asks for privilege and never runs `sudo`:
//! reaching the applied branch is the operator's decision, through the
//! product's own privilege path — on macOS the Aitmproxy app's packet-capture
//! helper (spec `2026-10-31-l4-capture-privilege-design`), on Linux
//! `cap_net_raw,cap_net_admin` on the test binary or a rig that has them.
//!
//! # Why the numbers are what they are
//!
//! * **Rate.** Both scope entries carry `pps 200`/`burst 200`, and the test's
//!   [`L4Config`] also raises `global_inject_pps` to 200. The tool-wide bucket
//!   defaults to 100, and the 100-case clean test mints 105 permits: left at
//!   the default the run would still pass, but every permit past the first
//!   hundred would wait on the rate limiter instead of measuring the service.
//!   `max_packet_bytes` and `max_packets_per_call` stay at their defaults.
//! * **ICMP generation is rate-limited, so the lane paces the point.** On
//!   macOS `net.inet.icmp.icmplim` (default 250 per second) sits far above the
//!   20 cases the reaction tests send. Linux limits ICMP errors per
//!   destination (`net.ipv4.icmp_ratelimit`, 1000 ms between errors to one
//!   peer after a small burst, with `icmp_ratemask` covering
//!   destination-unreachable, plus the global
//!   `icmp_msgs_per_sec`/`icmp_msgs_burst` budget the lane's liveness probes
//!   draw from as well), and the first real rig run read most cases as
//!   `silence` because of it. Spec amendment 46 answers that: a point whose
//!   baseline is an ICMP error is **paced** — consecutive cases, liveness
//!   probes and replays on it are spaced at least `l4.icmp_pace_ms` apart
//!   (default 1100 ms, floor 1000 ms). The closed-UDP test therefore asserts
//!   that **every** one of its 20 cases was classified `icmp(3,3)`, and that
//!   the paced run took at least `19 x 1100 ms`; it prints the elapsed time
//!   and the class histogram. A silent case on such a point is recorded as
//!   `no_reply (icmp_ratelimit)` and is never a crash candidate, so a closed
//!   port can never yield `l4-crash` (spec D8.4).
//! * **The capture sees the stimulus itself.** On Linux `lo` libpcap delivers
//!   the RX copy of every frame the lane injects, and macOS `lo0` BPF reports
//!   sent frames too, so the first frame a reply capture reads is the lane's
//!   own stimulus. The first real run of this file (Ubuntu 24.04, 2026-11-01)
//!   found `send_recv` classifying that frame as `Other` and every case as
//!   `protocol_error`; the echo test still passed because it only checked
//!   verdicts and counters. These tests now read every case's class through
//!   `PacketLane::state()` and assert the classification itself.
//! * **Linux works unchanged.** The interface comes from
//!   `discover::loopback_interface()` (`lo0` on macOS, `lo` on Linux) and the
//!   link framing from `link_framing`, which picks Ethernet for `DLT_EN10MB`
//!   loopback devices, so the same three tests run on a Linux rig that grants
//!   `CAP_NET_RAW` to the test binary.

use std::net::{IpAddr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use aitm_proto_l4::backend::pcap::PcapBackend;
use aitm_proto_l4::backend::CaptureInjectBackend;
use aitm_proto_l4::config::L4Config;
use aitm_proto_l4::guard::L4Guard;
use aitm_proto_l4::types::{
    IpCidr, L4Capability, L4Direction, L4ScopeEntry, L4ScopeId, L4ScopeSource, PortRange, RateCap,
};
use aitm_scan_l4_packet::checks::{CRASH_CHECK_ID, REACTION_CHECK_ID};
use aitm_scan_l4_packet::discover::{loopback_interface, probe_privilege};
use aitm_scan_l4_packet::lane::PacketLane;
use aitm_scan_l4_packet::oracle::CaseClass;
use aitm_scan_l4_packet::state::{CaseRecord, PointRun};
use aitm_scan_l4_packet::testing::{fields, l4_profile, tcp_target, udp_target, TestJob};
use aitm_scan_model::{
    Discovery, InsertionPoint, JobCtx, L4Counters, L4Oracle, Lane, Outcome, ProbeHost, ScanProfile,
    Verdict,
};

/// The opt-in variable the operator sets to run the live lane.
const OPT_IN: &str = "AITM_L4_TESTS";

/// The per-entry and tool-wide injection rate the live lane runs at.
const LIVE_PPS: u32 = 200;

/// The SKIP the harness prints when the operator did not opt in (plan task 12).
const SKIP_NOT_OPTED_IN: &str =
    "SKIP 77: AITM_L4_TESTS is not set; the live loopback test needs the real pcap backend";

/// The live lane over the real [`PcapBackend`], or `None` after printing
/// [`SKIP_NOT_OPTED_IN`] when the operator did not opt in.
///
/// The guard admits `127.0.0.0/8` on every port of the platform loopback
/// interface, outbound `Inject` and inbound `Capture`, and nothing else. Its
/// `self_ports` stay empty on purpose: no core runs in this test, so there is
/// no listener for the capture's self-exclusion to protect.
fn live_lane() -> Option<(PacketLane, Arc<L4Guard>)> {
    if std::env::var(OPT_IN).ok().as_deref() != Some("1") {
        println!("{SKIP_NOT_OPTED_IN}");
        return None;
    }

    let interface = loopback_interface();
    let entry = |direction, capability| L4ScopeEntry {
        id: L4ScopeId::new(),
        cidr: IpCidr {
            addr: IpAddr::from([127, 0, 0, 0]),
            prefix: 8,
        },
        ports: PortRange {
            lo: 0,
            hi: u16::MAX,
        },
        interface: interface.to_string(),
        direction,
        capability,
        inject_rate: RateCap {
            pps: LIVE_PPS,
            burst: LIVE_PPS,
        },
        source: L4ScopeSource::Config,
    };
    let guard = Arc::new(L4Guard::new(&L4Config {
        enabled: true,
        scope: vec![
            entry(L4Direction::Outbound, L4Capability::Inject),
            entry(L4Direction::Inbound, L4Capability::Capture),
        ],
        // The tool-wide bucket defaults to 100 and would throttle the 105
        // permits of the clean test; the per-entry caps above stay the real
        // ceiling.
        global_inject_pps: LIVE_PPS,
        ..L4Config::default()
    }));

    let backend: Arc<dyn CaptureInjectBackend> = Arc::new(PcapBackend::new());
    let lane = PacketLane::with_backend(Arc::clone(&guard), None, backend)
        .with_default_fields(fields(&["raw"]));
    Some((lane, guard))
}

/// The privilege SKIP line for a `lane_unavailable` refusal `err`. The
/// privilege path it names is the product's own: on macOS the app's
/// packet-capture helper (spec `2026-10-31-l4-capture-privilege-design`), on
/// Linux the capabilities on the test binary; never a third-party tool.
fn privilege_skip_line(err: &str) -> String {
    format!(
        "SKIP 77: L4 packet lane live proof skipped: {err}. BPF is root-only on this host (/dev/bpf* are crw------- root); on macOS the Aitmproxy app's packet-capture helper grants it (spec 2026-10-31-l4-capture-privilege-design); on Linux give the test binary cap_net_raw,cap_net_admin or use a rig that has them. This session never obtains privilege itself."
    )
}

/// Print the plan's privilege SKIP verbatim, or fail the test when the lane
/// refused for any other reason.
fn skip_or_fail(err: &str) {
    assert!(
        err.contains("lane_unavailable"),
        "the live lane refused for a reason other than pcap privilege: {err}"
    );
    println!("{}", privilege_skip_line(err));
}

/// Whether the lane can open a capture here, printing the privilege SKIP when
/// it cannot.
///
/// This is the same probe `discover` runs before it plans anything, called
/// first and on its own so the decision to skip is made before a test binds a
/// socket: a host that denies pcap often denies the loopback bind too, and the
/// operator is owed the privilege SKIP rather than an unrelated panic.
fn can_capture(guard: &L4Guard) -> bool {
    match probe_privilege(guard, &PcapBackend::new(), loopback_interface()) {
        Ok(()) => true,
        Err(err) => {
            skip_or_fail(&err.to_string());
            false
        }
    }
}

/// Plan the profile's targets, or print the privilege SKIP and return `None`.
async fn discover_or_skip(
    lane: &PacketLane,
    profile: &ScanProfile,
    job: &Arc<TestJob>,
) -> Option<Discovery> {
    match lane.discover(&profile.target, job.as_ref()).await {
        Ok(discovery) => Some(discovery),
        Err(err) => {
            skip_or_fail(&err.to_string());
            None
        }
    }
}

/// Run the lane's check with `id` over `point`.
async fn run_check(
    lane: &PacketLane,
    id: &str,
    point: &InsertionPoint,
    host: &dyn ProbeHost,
) -> Verdict {
    let checks = lane.checks();
    let check = checks
        .iter()
        .find(|check| check.meta().id == id)
        .unwrap_or_else(|| panic!("the lane lists the {id} check"));
    check.run(point, host).await
}

/// The finished run of `point`, as both checks cached it in the lane's state.
fn point_run(lane: &PacketLane, job: &TestJob, point: &InsertionPoint) -> Arc<PointRun> {
    lane.state()
        .expect("the live lane has its L4 handles")
        .run(job.job_id(), &point.id)
        .expect("the checks drove the point's run")
}

/// The run's case classes with their counts, in first-seen order, as the
/// oracle labels them (`clean`, `icmp(3,3)`, `reset`, `protocol_error`,
/// `silence`); an unsent case counts under `unsent`.
fn class_histogram(run: &PointRun) -> Vec<(String, u32)> {
    let mut seen: Vec<(String, u32)> = Vec::new();
    for case in &run.cases {
        let label = case
            .class()
            .map_or_else(|| "unsent".to_string(), |class| class.label());
        if let Some(entry) = seen.iter_mut().find(|(seen, _)| *seen == label) {
            entry.1 += 1;
        } else {
            seen.push((label, 1));
        }
    }
    seen
}

/// How many of the run's cases the oracle read as `class`.
fn count_class(run: &PointRun, class: CaseClass) -> usize {
    run.cases
        .iter()
        .filter(|case| case.class() == Some(class))
        .count()
}

/// A loopback UDP port with nothing behind it: bind it, read it, let it go.
///
/// The kernel can hand the port out again, but on an idle loopback it stays
/// closed for the length of a test, which is the condition AC T5-2a needs.
fn closed_udp_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("a loopback udp port");
    let port = socket.local_addr().expect("the bound address").port();
    drop(socket);
    port
}

/// The same for TCP: a port whose listener is already gone, so the kernel
/// answers a SYN with RST.
fn closed_tcp_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback tcp port");
    let port = listener.local_addr().expect("the bound address").port();
    drop(listener);
    port
}

/// A real UDP echo service on loopback: every datagram comes straight back.
///
/// The reader wakes every 200 ms so the stop flag is seen promptly, and
/// [`EchoService::stop`] joins the thread.
struct EchoService {
    port: u16,
    stop: Arc<AtomicBool>,
    handle: thread::JoinHandle<()>,
}

impl EchoService {
    fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("a loopback udp port");
        socket
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("a read timeout on the echo socket");
        let port = socket.local_addr().expect("the bound address").port();

        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while !flag.load(Ordering::Relaxed) {
                // A timeout is the common case and is not an error here; any
                // other recv error is transient on loopback, so both just
                // re-check the stop flag.
                if let Ok((read, from)) = socket.recv_from(&mut buf) {
                    if let Some(payload) = buf.get(..read) {
                        let _ = socket.send_to(payload, from);
                    }
                }
            }
        });

        Self { port, stop, handle }
    }

    fn stop(self) {
        self.stop.store(true, Ordering::Relaxed);
        self.handle.join().expect("the echo thread joins");
    }
}

/// Tester (stage 5): the privilege SKIP is printed only for a
/// `lane_unavailable` refusal; this runs without privilege and without the
/// opt-in, so the SKIP wording is pinned in every gate run. The privilege path
/// it recommends is the product's own helper on macOS and the capabilities on
/// Linux (Matt's decision, T5 live proof), never Wireshark's ChmodBPF.
#[test]
fn skip_or_fail_prints_the_privilege_skip_for_lane_unavailable() {
    skip_or_fail("lane_unavailable: pcap on lo0: no capture privilege (mock)");
    skip_or_fail("the engine wrapped it: lane_unavailable: pcap on lo: Operation not permitted");

    let line = privilege_skip_line("lane_unavailable: pcap on lo0: no capture privilege (mock)");
    assert_eq!(
        line,
        "SKIP 77: L4 packet lane live proof skipped: lane_unavailable: pcap on lo0: no capture privilege (mock). BPF is root-only on this host (/dev/bpf* are crw------- root); on macOS the Aitmproxy app's packet-capture helper grants it (spec 2026-10-31-l4-capture-privilege-design); on Linux give the test binary cap_net_raw,cap_net_admin or use a rig that has them. This session never obtains privilege itself."
    );
    assert!(
        !line.contains("ChmodBPF") && !line.contains("access_bpf"),
        "the SKIP never recommends a third-party privilege path: {line}"
    );
}

/// Tester (stage 5): any other refusal — out of scope, an invalid profile, a
/// guard refusal — fails the live test instead of hiding behind a SKIP.
#[test]
#[should_panic(expected = "the live lane refused for a reason other than pcap privilege")]
fn skip_or_fail_fails_the_test_on_any_other_refusal() {
    skip_or_fail(
        "out_of_scope: 127.0.0.1:9/udp: no L4 scope entry with Inject (outbound) and Capture (inbound) covers it",
    );
}

#[test]
#[should_panic(expected = "the live lane refused for a reason other than pcap privilege")]
fn skip_or_fail_fails_the_test_on_an_unavailable_stop_that_is_not_the_lane_code() {
    // The runner's `l4 unavailable:` stop reason is not the D3 `lane_unavailable` code.
    skip_or_fail("l4 unavailable: the send_recv task did not finish");
}

/// Tester (stage 5): `live_lane` builds a lane exactly when the operator
/// opted in; without the variable it prints the not-opted-in SKIP and sends
/// nothing (no privilege is needed to construct a `PcapBackend`).
#[test]
fn live_lane_follows_the_opt_in_variable() {
    let opted_in = std::env::var(OPT_IN).ok().as_deref() == Some("1");
    let lane = live_lane();
    assert_eq!(lane.is_some(), opted_in);
    if let Some((lane, guard)) = lane {
        assert_eq!(lane.lane(), aitm_scan_model::LaneKind::L4Packet);
        assert_eq!(guard.list_scope().len(), 2);
        assert!(guard.self_ports().is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs raw pcap privilege; run with AITM_L4_TESTS=1 and -- --ignored"]
async fn live_closed_udp_port_yields_icmp_3_3() {
    let Some((lane, guard)) = live_lane() else {
        return;
    };
    if !can_capture(&guard) {
        return;
    }

    let profile = l4_profile(vec![udp_target(closed_udp_port())], 20);
    let job = TestJob::new(profile.clone());
    let Some(discovery) = discover_or_skip(&lane, &profile, &job).await else {
        return;
    };
    assert_eq!(discovery.points.len(), 1, "one raw point for one target");
    let point = discovery.points[0].clone();
    let host = lane
        .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
        .expect("the lane hosts the point it minted");

    // The lane paces an ICMP-baseline point by `l4.icmp_pace_ms`, raised to
    // the `ICMP_PACE_FLOOR_MS` floor; the profile default is 1100 ms, so the
    // 20 cases cost at least nineteen gaps of it (spec amendment 46).
    assert_eq!(profile.l4.icmp_pace_ms, 1100, "the profile default pace");
    let pace = Duration::from_millis(u64::from(profile.l4.icmp_pace_ms));
    let started = Instant::now();
    let reaction = run_check(&lane, REACTION_CHECK_ID, &point, host.as_ref()).await;
    let crash = run_check(&lane, CRASH_CHECK_ID, &point, host.as_ref()).await;
    let elapsed = started.elapsed();
    let counters = lane.counters(job.job_id());
    let stats = lane.stats(job.job_id());
    let run = point_run(&lane, &job, &point);
    let histogram = class_histogram(&run);
    let icmp_3_3 = count_class(
        &run,
        CaseClass::Icmp {
            icmp_type: 3,
            code: 3,
        },
    );
    let silent = count_class(&run, CaseClass::Silence);

    println!("reaction: {:?} | {}", reaction.outcome, reaction.detail);
    println!("crash: {:?} | {}", crash.outcome, crash.detail);
    println!("counters: {counters:?}");
    println!("stats: {stats:?}");
    println!("classes: {histogram:?}");
    println!(
        "closed udp port: {icmp_3_3} of {} cases drew icmp(3,3), {silent} were silent, {} were noted no_reply (icmp_ratelimit); paced at {pace:?}, elapsed {elapsed:?}; baseline {:?}, crash {:?}, stopped {:?}",
        run.cases.len(),
        run.no_reply_count(),
        run.baseline,
        run.crash.as_ref().map(|c| (c.case_index, c.recovered)),
        run.stopped
    );

    assert_eq!(
        icmp_3_3, 20,
        "under the pace of amendment 46 every case draws the kernel's port-unreachable; classes {histogram:?}, elapsed {elapsed:?}"
    );
    assert_eq!(
        counters,
        Some(L4Counters {
            cases: 20,
            crashes: 0,
            liveness_failures: 0,
            retired_elements: 0,
        }),
        "a closed port costs no liveness probe and no crash; stats {stats:?}"
    );
    assert!(
        elapsed >= 19 * pace,
        "twenty paced cases cost at least {:?}; the run took {elapsed:?} (classes {histogram:?})",
        19 * pace
    );
    assert_eq!(reaction.outcome, Outcome::Vulnerable);
    let l4 = reaction
        .evidence
        .l4
        .as_ref()
        .expect("the reaction evidence");
    assert_eq!(
        l4.oracle,
        L4Oracle::Icmp {
            icmp_type: 3,
            code: 3
        },
        "the kernel's port-unreachable is icmp(3,3)"
    );
    assert_eq!(
        crash.outcome,
        Outcome::Clean,
        "a closed port never crashes; the lane reported one: counters {counters:?}, stats {stats:?}, classes {histogram:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs raw pcap privilege; run with AITM_L4_TESTS=1 and -- --ignored"]
async fn live_closed_tcp_port_yields_reset() {
    let Some((lane, guard)) = live_lane() else {
        return;
    };
    if !can_capture(&guard) {
        return;
    }

    let profile = l4_profile(vec![tcp_target(closed_tcp_port())], 20);
    let job = TestJob::new(profile.clone());
    let Some(discovery) = discover_or_skip(&lane, &profile, &job).await else {
        return;
    };
    assert_eq!(discovery.points.len(), 1, "one raw point for one target");
    let point = discovery.points[0].clone();
    let host = lane
        .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
        .expect("the lane hosts the point it minted");

    let reaction = run_check(&lane, REACTION_CHECK_ID, &point, host.as_ref()).await;
    let crash = run_check(&lane, CRASH_CHECK_ID, &point, host.as_ref()).await;
    let counters = lane.counters(job.job_id());
    let stats = lane.stats(job.job_id());
    let run = point_run(&lane, &job, &point);
    let histogram = class_histogram(&run);
    let resets = count_class(&run, CaseClass::Reset);
    let silent = count_class(&run, CaseClass::Silence);

    println!("reaction: {:?} | {}", reaction.outcome, reaction.detail);
    println!("crash: {:?} | {}", crash.outcome, crash.detail);
    println!("counters: {counters:?}");
    println!("stats: {stats:?}");
    println!("classes: {histogram:?}");
    println!(
        "closed tcp port: {resets} of {} cases drew a reset, {silent} were silent; baseline {:?}, crash {:?}, stopped {:?}",
        run.cases.len(),
        run.baseline,
        run.crash.as_ref().map(|c| (c.case_index, c.recovered)),
        run.stopped
    );

    assert!(
        resets >= 1,
        "at least one case must be classified reset by the kernel's answer to a syn on a closed port; classes {histogram:?}"
    );
    assert_eq!(reaction.outcome, Outcome::Vulnerable);
    let l4 = reaction
        .evidence
        .l4
        .as_ref()
        .expect("the reaction evidence");
    assert_eq!(
        l4.oracle,
        L4Oracle::Reset,
        "the kernel answers a syn to a closed port with rst"
    );
    assert_eq!(
        crash.outcome,
        Outcome::Clean,
        "a closed port never crashes; the lane reported one: counters {counters:?}, stats {stats:?}, classes {histogram:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs raw pcap privilege; run with AITM_L4_TESTS=1 and -- --ignored"]
async fn live_udp_echo_hundred_clean() {
    let Some((lane, guard)) = live_lane() else {
        return;
    };
    if !can_capture(&guard) {
        return;
    }

    let echo = EchoService::start();
    let profile = l4_profile(vec![udp_target(echo.port)], 100);
    let job = TestJob::new(profile.clone());
    let Some(discovery) = discover_or_skip(&lane, &profile, &job).await else {
        echo.stop();
        return;
    };
    let points = discovery.points.len();
    let point = discovery.points[0].clone();
    let host = lane
        .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
        .expect("the lane hosts the point it minted");

    let crash = run_check(&lane, CRASH_CHECK_ID, &point, host.as_ref()).await;
    let reaction = run_check(&lane, REACTION_CHECK_ID, &point, host.as_ref()).await;
    let counters = lane.counters(job.job_id());
    let stats = lane.stats(job.job_id());
    let run = point_run(&lane, &job, &point);
    let histogram = class_histogram(&run);

    // Join the service before asserting, so a failed expectation never leaves
    // the echo thread behind.
    echo.stop();

    println!("crash: {:?} | {}", crash.outcome, crash.detail);
    println!("reaction: {:?} | {}", reaction.outcome, reaction.detail);
    println!("counters: {counters:?}");
    println!("stats: {stats:?}");
    println!("classes: {histogram:?}");

    assert_eq!(points, 1, "one raw point for one target");
    assert_eq!(crash.outcome, Outcome::Clean, "the echo service survives");
    assert_eq!(
        reaction.outcome,
        Outcome::Clean,
        "an echo is not a reaction"
    );
    assert_eq!(
        counters,
        Some(L4Counters {
            cases: 100,
            crashes: 0,
            liveness_failures: 0,
            retired_elements: 0,
        })
    );

    // The classification itself, not just the verdicts: every one of the 100
    // cases was answered by the echo service and read as clean — which is
    // what the first Linux run did not have (every case was protocol_error,
    // the lane's own stimulus mistaken for the reply).
    assert_eq!(run.cases.len(), 100, "classes {histogram:?}");
    assert_eq!(
        run.baseline,
        Some(CaseClass::Clean),
        "the unmutated seed echoes"
    );
    let not_clean: Vec<(u32, Option<CaseClass>)> = run
        .cases
        .iter()
        .filter(|case| case.class() != Some(CaseClass::Clean))
        .map(|case: &CaseRecord| (case.index, case.class()))
        .collect();
    assert!(
        not_clean.is_empty(),
        "every echoed case is classified clean; these were not: {not_clean:?}; classes {histogram:?}"
    );
    assert_eq!(
        stats.as_ref().map(|stats| stats.timeouts),
        Some(0),
        "no echoed case timed out: {stats:?}"
    );
}
