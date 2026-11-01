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
//! reaching the applied branch is the operator's decision (Wireshark's
//! ChmodBPF / the `access_bpf` group on macOS, `CAP_NET_RAW` on Linux).
//!
//! # Why the numbers are what they are
//!
//! * **Rate.** Both scope entries carry `pps 200`/`burst 200`, and the test's
//!   [`L4Config`] also raises `global_inject_pps` to 200. The tool-wide bucket
//!   defaults to 100, and the 100-case clean test mints 105 permits: left at
//!   the default the run would still pass, but every permit past the first
//!   hundred would wait on the rate limiter instead of measuring the service.
//!   `max_packet_bytes` and `max_packets_per_call` stay at their defaults.
//! * **ICMP generation is rate-limited on macOS** (`net.inet.icmp.icmplim`,
//!   default 250 per second). The two reaction tests send 20 cases at the
//!   default 500 ms reply window, which stays far below that ceiling, so the
//!   kernel answers every one and a silent case means something real.
//! * **Linux works unchanged.** The interface comes from
//!   `discover::loopback_interface()` (`lo0` on macOS, `lo` on Linux) and the
//!   link framing from `link_framing`, which picks Ethernet for `DLT_EN10MB`
//!   loopback devices, so the same three tests run on a Linux rig that grants
//!   `CAP_NET_RAW` to the test binary.

use std::net::{IpAddr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

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

/// Print the plan's privilege SKIP verbatim, or fail the test when the lane
/// refused for any other reason.
fn skip_or_fail(err: &str) {
    assert!(
        err.contains("lane_unavailable"),
        "the live lane refused for a reason other than pcap privilege: {err}"
    );
    println!(
        "SKIP 77: L4 packet lane live proof skipped: {err}. BPF is root-only on this host (/dev/bpf* are crw------- root); grant it via Wireshark's ChmodBPF (the access_bpf group) or run on a Linux rig with CAP_NET_RAW. This session never obtains privilege itself."
    );
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
/// opt-in, so the SKIP wording is pinned in every gate run.
#[test]
fn skip_or_fail_prints_the_privilege_skip_for_lane_unavailable() {
    skip_or_fail("lane_unavailable: pcap on lo0: no capture privilege (mock)");
    skip_or_fail("the engine wrapped it: lane_unavailable: pcap on lo: Operation not permitted");
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

    let reaction = run_check(&lane, REACTION_CHECK_ID, &point, host.as_ref()).await;
    let crash = run_check(&lane, CRASH_CHECK_ID, &point, host.as_ref()).await;

    println!("reaction: {:?} | {}", reaction.outcome, reaction.detail);
    println!("counters: {:?}", lane.counters(job.job_id()));
    println!("stats: {:?}", lane.stats(job.job_id()));

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
    assert_eq!(crash.outcome, Outcome::Clean, "a closed port never crashes");
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

    println!("reaction: {:?} | {}", reaction.outcome, reaction.detail);
    println!("counters: {:?}", lane.counters(job.job_id()));
    println!("stats: {:?}", lane.stats(job.job_id()));

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
    assert_eq!(crash.outcome, Outcome::Clean, "a closed port never crashes");
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

    // Join the service before asserting, so a failed expectation never leaves
    // the echo thread behind.
    echo.stop();

    println!("crash: {:?} | {}", crash.outcome, crash.detail);
    println!("reaction: {:?} | {}", reaction.outcome, reaction.detail);
    println!("counters: {counters:?}");
    println!("stats: {stats:?}");

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
}
