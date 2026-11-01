//! Lane-level live proof against T10's real speakers; needs AITM_T10_CONTROL; not the bus-level acceptance run.
//!
//! Plan task 23a. This drives the **real** [`L4StreamLane`] — the real
//! [`TokioStreamClient`] over real sockets, behind a real `L4Guard` — against
//! T10's real `aitm-testtarget-serve --l4` speakers, and reads T10's own
//! control origin as the independent observer. It is the interim proof while
//! the bus-level engine (track T1b) is unavailable: it observes what the
//! spec's Verification row **T6-4** asks for, but it does not go over the bus
//! and it produces no `scan.issue`, so it is *not* the acceptance run for
//! T6-1..T6-5.
//!
//! Run it through `tests/live_t10.sh`, which starts the target, exports
//! `AITM_T10_CONTROL` and runs both modes. Without that variable the test
//! prints `SKIP: AITM_T10_CONTROL not set` and passes, which is all it can do
//! in a sandbox that cannot bind or reach a loopback port.
//!
//! Authorised scope: a first-party scanner against this project's own seeded
//! loopback test target, bounded (120 cases per service, an 8 KiB/s pacer,
//! three reproductions) and non-destructive (the denylist, asserted at zero).
//!
//! Nothing here prints or stores a message byte: only lengths, the observer's
//! own SHA-256 hashes, mutation chains, field paths and counters (spec C11).

mod common;

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use aitm_scan_l4_stream::client::{StreamClient, TokioStreamClient};
use aitm_scan_l4_stream::lane_with_client;
use aitm_scan_l4_stream::state::JobState;
use aitm_scan_model::{
    builtin_profiles, Confidence, InsertionPoint, JobCtx, L4TargetSpec, L4Transport, Lane, Outcome,
    ProfileTarget, ScanProfile, Verdict,
};
use serde_json::{json, Value};

use common::{wildcard_guard, TestJob};

/// T10's eight stream-lane speakers, in the registry's delivery order
/// (`tlv resp memcached dns modbus mqtt smtp ftp`). `l4-udp-payload-crash` is
/// deliberately absent: its grammar is `raw`, which is track T5's.
const SPEAKERS: [&str; 8] = [
    "l4-tlv-crash",
    "l4-resp",
    "l4-memcached",
    "l4-dns-fault",
    "l4-modbus",
    "l4-mqtt",
    "l4-smtp",
    "l4-ftp",
];

/// The lane's three checks, run against every point in this order.
const CHECK_IDS: [&str; 3] = ["l4-crash", "l4-parser-fault", "l4-latency-outlier"];

/// The two verdict classes that prove a seeded fault on V (spec T6-4).
const PROVING_CLASSES: [&str; 2] = ["l4-crash", "l4-parser-fault"];

/// At most this many discovered points per speaker, so one service's run stays
/// inside a few minutes.
const MAX_POINTS: usize = 6;

/// The profile's case budget per speaker.
const CASES: u32 = 120;

/// The profile's pacer, low enough that T6-4's bytes/s bound is observable.
const MAX_BYTES_PER_S: u32 = 8192;

/// One MTU of slack on the bytes/s bound, for a message that straddles a
/// second boundary of the observer's `ts_ms / 1000` bucketing.
const BPS_SLACK: u64 = 1500;

/// The profile's bounded reproduction count.
const REPRODUCE_COUNT: u32 = 3;

/// Per-service wall clock for the job.
const JOB_DEADLINE: Duration = Duration::from_secs(600);

/// Budget units; the lane charges per case and per liveness probe.
const JOB_BUDGET: u32 = 100_000;

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a running `aitm-testtarget-serve --l4`; drive it with tests/live_t10.sh"]
async fn live_against_t10_speakers() {
    let Ok(origin) = std::env::var("AITM_T10_CONTROL") else {
        println!("SKIP: AITM_T10_CONTROL not set");
        return;
    };

    let mode = mode_of(&origin);
    let services = services_of(&origin);
    let out_dir = out_dir();
    std::fs::create_dir_all(&out_dir)
        .unwrap_or_else(|err| panic!("create the report directory {}: {err}", out_dir.display()));

    println!(
        "LIVE mode={mode} control={origin} out={}",
        out_dir.display()
    );

    let mut failures: Vec<String> = Vec::new();
    let mut summaries: Vec<String> = Vec::new();

    for name in SPEAKERS {
        let Some(service) = services.get(name) else {
            failures.push(format!("T10 lists no service `{name}` on GET /services"));
            continue;
        };
        let outcome = run_service(&origin, mode, name, service).await;
        let path = out_dir.join(format!("{mode}-{name}.json"));
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&outcome.report)
                .unwrap_or_else(|err| panic!("serialise the {name} report: {err}")),
        )
        .unwrap_or_else(|err| panic!("write {}: {err}", path.display()));
        println!("{}", outcome.summary);
        summaries.push(outcome.summary);
        failures.extend(outcome.failures);
    }

    println!("--- LIVE {mode} summary ---");
    for line in &summaries {
        println!("{line}");
    }

    assert!(
        failures.is_empty(),
        "the live {mode} run against T10's speakers failed {count} assertion(s):\n  {joined}",
        count = failures.len(),
        joined = failures.join("\n  "),
    );
}

// ---------------------------------------------------------------------------
// One speaker
// ---------------------------------------------------------------------------

/// What T10's `/services` says about one speaker.
struct Service {
    proto: L4Transport,
    ip: String,
    port: u16,
    addr: String,
    grammar: String,
}

/// Everything one speaker's run produced.
struct ServiceRun {
    report: Value,
    summary: String,
    failures: Vec<String>,
}

/// One verdict, flattened for the report.
struct PointVerdict {
    point_id: String,
    path: String,
    check: String,
    verdict: Verdict,
}

/// Drive the lane against one speaker, then read T10's log for it.
async fn run_service(origin: &str, mode: &str, name: &str, service: &Service) -> ServiceRun {
    let mut failures: Vec<String> = Vec::new();

    // A clean observer window per speaker.
    let reset = control_json(origin, "POST", "/reset");
    assert_eq!(
        reset["reset"],
        json!(true),
        "POST /reset before {name} did not reset"
    );

    let guard = wildcard_guard(&[service.port]);
    let profile = profile_for(service);
    let target: ProfileTarget = profile.target.clone();
    let job_id = format!("live-{name}");
    let lane = lane_with_client(
        Some(guard),
        None,
        Arc::new(TokioStreamClient) as Arc<dyn StreamClient>,
    );
    let job: Arc<dyn JobCtx> = Arc::new(
        TestJob::new(profile)
            .with_job_id(&job_id)
            .with_marker(&format!("live-{name}"))
            .with_budget(JOB_BUDGET)
            .with_deadline(Instant::now() + JOB_DEADLINE),
    );

    let points: Vec<InsertionPoint> = match lane.discover(&target, job.as_ref()).await {
        Ok(discovery) => discovery.points,
        Err(err) => {
            failures.push(format!("{name}: discovery failed: {err}"));
            Vec::new()
        }
    };
    let points_found = points.len();
    let checks = lane.checks();

    let mut verdicts: Vec<PointVerdict> = Vec::new();
    let mut stopped_at: Option<String> = None;

    'points: for point in points.iter().take(MAX_POINTS) {
        let path = point.path.clone().unwrap_or_else(|| point.name.clone());
        for id in CHECK_IDS {
            let Some(check) = checks.iter().find(|check| check.meta().id == id) else {
                failures.push(format!("{name}: the lane ships no `{id}` check"));
                continue;
            };
            let host = match lane.probe_host_for(point, Arc::clone(&job)) {
                Ok(host) => host,
                Err(err) => {
                    failures.push(format!("{name}: no probe host for `{path}`/{id}: {err}"));
                    continue;
                }
            };
            let verdict = check.run(point, host.as_ref()).await;
            let proving = verdict.outcome == Outcome::Vulnerable && PROVING_CLASSES.contains(&id);
            verdicts.push(PointVerdict {
                point_id: point.id.clone(),
                path: path.clone(),
                check: id.to_string(),
                verdict,
            });
            // V mode: the fault is proven; stop driving this speaker rather
            // than keep hammering a service that is already down for its
            // crash window.
            if mode == "V" && proving {
                stopped_at = Some(format!(
                    "{id}@{path} (point {point_id})",
                    point_id = point.id
                ));
                break 'points;
            }
        }
    }

    let points_run = verdicts
        .iter()
        .map(|entry| entry.point_id.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .len();

    let state = lane.state().get(&job_id);
    let observed = observe(origin, name);

    // --- the assertions (spec Verification, row T6-4) ---------------------

    if observed.denylisted != 0 {
        failures.push(format!(
            "{name}: T10 logged {count} message(s) classified `denylisted`; the denylist must refuse every one before it is sent",
            count = observed.denylisted,
        ));
    }

    let proving_verdicts: Vec<&PointVerdict> = verdicts
        .iter()
        .filter(|entry| {
            entry.verdict.outcome == Outcome::Vulnerable
                && PROVING_CLASSES.contains(&entry.check.as_str())
        })
        .collect();
    let any_vulnerable: Vec<&PointVerdict> = verdicts
        .iter()
        .filter(|entry| entry.verdict.outcome == Outcome::Vulnerable)
        .collect();

    match mode {
        "V" => {
            if proving_verdicts.is_empty() {
                failures.push(format!(
                    "{name}: V mode recorded no `l4-crash` or `l4-parser-fault` verdict over {points_run}/{points_found} point(s); outcomes were {outcomes}",
                    outcomes = render_outcomes(&verdicts),
                ));
            }
            for entry in &proving_verdicts {
                if entry.check != "l4-crash" {
                    continue;
                }
                if observed.downtime_ms.is_empty() {
                    failures.push(format!(
                        "{name}: an `l4-crash` verdict at `{path}` but T10's log shows no downtime entry",
                        path = entry.path,
                    ));
                }
                match entry.verdict.evidence.l4.as_ref() {
                    Some(l4) if l4.reproduced.0 >= 1 => {}
                    Some(l4) => failures.push(format!(
                        "{name}: `l4-crash` at `{path}` reproduced {k}/{n} times; at least one reproduction is required",
                        path = entry.path,
                        k = l4.reproduced.0,
                        n = l4.reproduced.1,
                    )),
                    None => failures.push(format!(
                        "{name}: `l4-crash` at `{path}` carries no L4 evidence",
                        path = entry.path,
                    )),
                }
            }
        }
        "P" => {
            if !any_vulnerable.is_empty() {
                failures.push(format!(
                    "{name}: P mode must yield zero `Vulnerable` verdicts of any class, got {found}",
                    found = render_vulnerable(&any_vulnerable),
                ));
            }
            if !observed.downtime_ms.is_empty() {
                failures.push(format!(
                    "{name}: P mode must never take the speaker down; T10 logged {count} downtime window(s) {windows:?}",
                    count = observed.downtime_ms.len(),
                    windows = observed.downtime_ms,
                ));
            }
        }
        other => failures.push(format!("{name}: unknown mode `{other}`")),
    }

    let bps_ceiling = u64::from(MAX_BYTES_PER_S) + BPS_SLACK;
    if observed.max_bps > bps_ceiling {
        // Print the evidence before the run fails, so the Terminal log shows
        // which second overshot and by how much.
        println!("BPS {name}: ceiling {bps_ceiling} B/s; per-second client->server windows:");
        for (second, bytes) in &observed.windows {
            println!("  BPS {name}: window {second} = {bytes} B");
        }
        failures.push(format!(
            "{name}: the pacer let {max} B through in one second, over the {bps_ceiling} B/s ceiling ({MAX_BYTES_PER_S} + {BPS_SLACK} slack)",
            max = observed.max_bps,
        ));
    }

    let summary = format!(
        "LIVE {mode} {name} grammar={grammar} points={points_run}/{points_found} cases={cases} vulnerable=[{vulnerable}] downtime={downtime} denylisted={denylisted} max_bps={max_bps} accepts={accepts}",
        grammar = service.grammar,
        cases = state
            .as_ref()
            .map_or(0, |state| state.counters().cases),
        vulnerable = render_vulnerable(&any_vulnerable),
        downtime = observed.downtime_ms.len(),
        denylisted = observed.denylisted,
        max_bps = observed.max_bps,
        accepts = observed.accepts,
    );

    let report = json!({
        "mode": mode,
        "service": name,
        "grammar": service.grammar,
        "addr": service.addr,
        "proto": transport_name(service.proto),
        "selection": state.as_ref().map(|state| {
            locked(&state.selection)
                .iter()
                .map(|(node, why)| (node.clone(), Value::String(why.clone())))
                .collect::<serde_json::Map<String, Value>>()
        }),
        "points_found": points_found,
        "points_run": points_run,
        "stopped_at": stopped_at,
        "verdicts": verdicts.iter().map(verdict_json).collect::<Vec<Value>>(),
        "counters": state.as_ref().map(counters_json),
        "observer": observed.to_json(),
    });

    ServiceRun {
        report,
        summary,
        failures,
    }
}

/// `l4-stream-safe`, bounded as T6-4 asks, over this one speaker.
fn profile_for(service: &Service) -> ScanProfile {
    let mut profile = builtin_profiles()
        .into_iter()
        .find(|profile| profile.name == "l4-stream-safe")
        .expect("`l4-stream-safe` is a built-in profile");
    profile.l4.cases = CASES;
    profile.l4.max_bytes_per_s = MAX_BYTES_PER_S;
    profile.l4.reproduce_count = REPRODUCE_COUNT;
    profile.target = ProfileTarget {
        origins: Vec::new(),
        l4: vec![L4TargetSpec {
            ip: service.ip.clone(),
            port: service.port,
            proto: service.proto,
            grammar: Some(service.grammar.clone()),
        }],
    };
    profile
}

// ---------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------

/// One verdict as JSON: the `L4Evidence` without `sent_hex`, which is replaced
/// by its byte length (C11: no message byte leaves this process).
fn verdict_json(entry: &PointVerdict) -> Value {
    let evidence = entry.verdict.evidence.l4.as_ref().map(|l4| {
        json!({
            "sent_bytes": l4.sent_hex.len() / 2,
            "seed_id": l4.seed_id,
            "rng_seed": l4.rng_seed,
            "mutation_chain": l4.mutation_chain,
            "prior_messages": l4.prior_messages,
            "oracle": serde_json::to_value(l4.oracle).unwrap_or(Value::Null),
            "liveness_before": l4.liveness_before,
            "liveness_after": l4.liveness_after,
            "reproduced": [l4.reproduced.0, l4.reproduced.1],
            "scope_entry": l4.scope_entry,
        })
    });
    json!({
        "point_id": entry.point_id,
        "path": entry.path,
        "check": entry.check,
        "outcome": outcome_name(entry.verdict.outcome),
        "confidence": confidence_name(entry.verdict.confidence),
        "detail": entry.verdict.detail,
        "l4_evidence": evidence,
    })
}

/// The lane's counters for the job: `JobState::counters` plus the four the
/// engine does not carry on the wire.
fn counters_json(state: &Arc<JobState>) -> Value {
    use std::sync::atomic::Ordering;

    let counters = state.counters();
    json!({
        "cases": counters.cases,
        "crashes": counters.crashes,
        "liveness_failures": counters.liveness_failures,
        "retired_elements": counters.retired_elements,
        "cases_skipped_denylisted": state.cases_skipped_denylisted.load(Ordering::Relaxed),
        "liveness_probes": state.liveness_probes.load(Ordering::Relaxed),
        "rate_waits": state.rate_waits.load(Ordering::Relaxed),
    })
}

/// `class@path:chain0`, comma-joined, for the one-line summary.
fn render_vulnerable(entries: &[&PointVerdict]) -> String {
    entries
        .iter()
        .map(|entry| {
            let chain = entry
                .verdict
                .evidence
                .l4
                .as_ref()
                .and_then(|l4| l4.mutation_chain.first().cloned())
                .unwrap_or_else(|| "-".to_string());
            format!(
                "{check}@{path}:{chain}",
                check = entry.check,
                path = entry.path
            )
        })
        .collect::<Vec<String>>()
        .join(",")
}

/// `check@path=outcome`, comma-joined, for a failure message.
fn render_outcomes(entries: &[PointVerdict]) -> String {
    entries
        .iter()
        .map(|entry| {
            format!(
                "{check}@{path}={outcome}",
                check = entry.check,
                path = entry.path,
                outcome = outcome_name(entry.verdict.outcome),
            )
        })
        .collect::<Vec<String>>()
        .join(",")
}

fn outcome_name(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Vulnerable => "vulnerable",
        Outcome::Clean => "clean",
        Outcome::Inconclusive => "inconclusive",
        Outcome::Error => "error",
    }
}

fn confidence_name(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Tentative => "tentative",
        Confidence::Firm => "firm",
        Confidence::Certain => "certain",
    }
}

fn transport_name(proto: L4Transport) -> &'static str {
    match proto {
        L4Transport::Tcp => "tcp",
        L4Transport::Udp => "udp",
    }
}

/// A `JobState` mutex, read without caring about a poisoned lock.
fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `$AITM_T6_LIVE_OUT`, or `/tmp/claude/t6-live`.
fn out_dir() -> PathBuf {
    PathBuf::from(
        std::env::var("AITM_T6_LIVE_OUT").unwrap_or_else(|_| "/tmp/claude/t6-live".to_string()),
    )
}

// ---------------------------------------------------------------------------
// The independent observer: T10's control origin
// ---------------------------------------------------------------------------

/// What T10's `GET /log/l4?service=<name>` says happened.
struct Observed {
    accepts: usize,
    classified: BTreeMap<String, u64>,
    denylisted: u64,
    closes: usize,
    downtime_ms: Vec<i64>,
    /// Client->server bytes per `ts_ms / 1000` bucket.
    windows: BTreeMap<u64, u64>,
    max_bps: u64,
    dropped: u64,
}

impl Observed {
    fn to_json(&self) -> Value {
        json!({
            "accepts": self.accepts,
            "classified": self.classified,
            "denylisted": self.denylisted,
            "closes": self.closes,
            "downtime_count": self.downtime_ms.len(),
            "downtime_ms": self.downtime_ms,
            "client_to_server_bytes_per_second": self.windows,
            "max_bytes_per_second": self.max_bps,
            "dropped": self.dropped,
        })
    }
}

/// Read T10's per-service L4 log and summarise it.
fn observe(origin: &str, name: &str) -> Observed {
    let body = control_json(origin, "GET", &format!("/log/l4?service={name}"));
    summarise(
        &body["services"][name],
        body["dropped"].as_u64().unwrap_or(0),
    )
}

/// Summarise one service's four rings. Pure, so `observer_summarises_a_log`
/// can drive it without a socket.
fn summarise(service: &Value, dropped: u64) -> Observed {
    let mut classified: BTreeMap<String, u64> = BTreeMap::new();
    let mut windows: BTreeMap<u64, u64> = BTreeMap::new();
    for message in rows(service, "messages") {
        let token = message["classified"].as_str().unwrap_or("unknown");
        *classified.entry(token.to_string()).or_default() += 1;
        // `dir` is relative to the target, so `in` is client->server.
        if message["dir"].as_str() == Some("in") {
            let ts_ms = message["ts_ms"].as_u64().unwrap_or(0);
            let len = message["len"].as_u64().unwrap_or(0);
            *windows.entry(ts_ms / 1000).or_default() += len;
        }
    }

    let downtime_ms: Vec<i64> = rows(service, "downtime")
        .iter()
        .map(|entry| {
            let up = entry["up_at_ms"].as_i64().unwrap_or(0);
            let down = entry["down_at_ms"].as_i64().unwrap_or(0);
            up - down
        })
        .collect();

    Observed {
        accepts: rows(service, "accepts").len(),
        denylisted: classified.get("denylisted").copied().unwrap_or(0),
        closes: rows(service, "closes").len(),
        downtime_ms,
        max_bps: windows.values().copied().max().unwrap_or(0),
        windows,
        dropped,
        classified,
    }
}

/// One ring of a service's log, or an empty slice when the service has none.
fn rows<'a>(service: &'a Value, key: &str) -> &'a [Value] {
    service[key].as_array().map_or(&[], Vec::as_slice)
}

/// `GET /mode`, as `"V"` or `"P"`.
fn mode_of(origin: &str) -> &'static str {
    let body = control_json(origin, "GET", "/mode");
    match body["mode"].as_str() {
        Some("vulnerable") => "V",
        Some("patched") => "P",
        other => panic!("GET /mode returned {other:?}; expected `vulnerable` or `patched`"),
    }
}

/// `GET /services`, as the `l4`-role services keyed by name.
fn services_of(origin: &str) -> BTreeMap<String, Service> {
    let body = control_json(origin, "GET", "/services");
    let listed = body["services"]
        .as_array()
        .unwrap_or_else(|| panic!("GET /services has no `services` array"));
    let mut services = BTreeMap::new();
    for entry in listed {
        let Some(name) = entry["name"].as_str() else {
            continue;
        };
        if !SPEAKERS.contains(&name) {
            continue;
        }
        let addr = entry["addr"]
            .as_str()
            .unwrap_or_else(|| panic!("service `{name}` has no `addr`"));
        let (ip, port) = addr
            .rsplit_once(':')
            .unwrap_or_else(|| panic!("service `{name}` addr `{addr}` has no port"));
        let proto = match entry["proto"].as_str() {
            Some("tcp") => L4Transport::Tcp,
            Some("udp") => L4Transport::Udp,
            other => panic!("service `{name}` has proto {other:?}"),
        };
        let grammar = entry["grammar"]
            .as_str()
            .unwrap_or_else(|| panic!("service `{name}` names no grammar"));
        services.insert(
            name.to_string(),
            Service {
                proto,
                ip: ip.trim_matches(|c| c == '[' || c == ']').to_string(),
                port: port
                    .parse()
                    .unwrap_or_else(|err| panic!("service `{name}` port `{port}`: {err}")),
                addr: addr.to_string(),
                grammar: grammar.to_string(),
            },
        );
    }
    services
}

/// One request to T10's control origin, parsed as JSON.
fn control_json(origin: &str, method: &str, path: &str) -> Value {
    let body = control_request(origin, method, path);
    serde_json::from_str(&body)
        .unwrap_or_else(|err| panic!("{method} {path} returned a body that is not JSON: {err}"))
}

/// A minimal HTTP/1.1 request to T10's control origin, returning the body.
///
/// Hand-rolled on purpose: this crate has no HTTP client dependency and the
/// plan adds none. Two of T10's own rules shape it — the `Host` header must be
/// a loopback name, and an `Origin` header is refused as cross-origin — so the
/// request carries the authority as `host` and no `origin` at all. `connection:
/// close` means the body ends at EOF; a `content-length`, when present, bounds
/// it.
fn control_request(origin: &str, method: &str, path: &str) -> String {
    let authority = origin
        .trim_end_matches('/')
        .strip_prefix("http://")
        .unwrap_or_else(|| panic!("AITM_T10_CONTROL `{origin}` is not an `http://` origin"));
    let mut stream = TcpStream::connect(authority)
        .unwrap_or_else(|err| panic!("connect to T10's control origin {authority}: {err}"));
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap_or_else(|err| panic!("set a read timeout on {authority}: {err}"));
    let request = format!(
        "{method} {path} HTTP/1.1\r\nhost: {authority}\r\naccept: application/json\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .unwrap_or_else(|err| panic!("write {method} {path}: {err}"));
    stream
        .flush()
        .unwrap_or_else(|err| panic!("flush {method} {path}: {err}"));

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .unwrap_or_else(|err| panic!("read the response to {method} {path}: {err}"));

    parse_response(&raw, &format!("{method} {path}"))
}

/// The body of one HTTP/1.1 response, after checking its status is 200. Pure,
/// so `response_parser_reads_a_bounded_body` can drive it without a socket.
fn parse_response(raw: &[u8], what: &str) -> String {
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("{what} returned no header terminator"));
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let body = &raw[split + 4..];

    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("?");
    assert_eq!(
        status, "200",
        "{what} returned status {status}; head was:\n{head}"
    );

    let declared = head.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    });
    let body = match declared {
        Some(len) => {
            assert!(
                body.len() >= len,
                "{what} declared {len} body bytes but {got} arrived",
                got = body.len()
            );
            &body[..len]
        }
        None => body,
    };
    String::from_utf8(body.to_vec())
        .unwrap_or_else(|err| panic!("{what} returned a non-UTF-8 body: {err}"))
}

// ---------------------------------------------------------------------------
// Harness self-checks
// ---------------------------------------------------------------------------
//
// The live test above cannot run where nothing can bind or reach a loopback
// port, so its two pure parsers are driven here against literal inputs. These
// are not proof of anything about the lane; they stop the proof run from
// reporting nonsense when it finally does reach a target.

/// The response reader honours `content-length` and refuses a non-200.
#[test]
fn response_parser_reads_a_bounded_body() {
    // `connection: close` leaves trailing bytes after the declared body on
    // some stacks; the reader must cut at `content-length`, not at EOF.
    let raw = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nContent-Length: 14\r\n\r\n{\"reset\":true}trailing";
    assert_eq!(parse_response(raw, "POST /reset"), "{\"reset\":true}");

    // No `content-length`: the body is everything to EOF.
    let raw = b"HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n{\"mode\":\"vulnerable\"}";
    assert_eq!(
        parse_response(raw, "GET /mode"),
        "{\"mode\":\"vulnerable\"}"
    );

    // T10 answers a request carrying an `Origin` header with 403; that must
    // fail the run loudly rather than parse as an empty log.
    let raw =
        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 26\r\n\r\n{\"error\":\"cross-origin\"}\r\n\r\n";
    let refused = std::panic::catch_unwind(|| parse_response(raw, "GET /services"));
    assert!(refused.is_err(), "a 403 must fail the run");
}

/// The observer summary counts exactly what T10's four rings say.
#[test]
fn observer_summarises_a_log() {
    // Two client->server messages inside second 1 (300 + 500 = 800 B), one of
    // 100 B inside second 2, and a server->client reply that must not be
    // counted towards the client->server pacer bound.
    let service = json!({
        "accepts": [
            { "seq": 1, "ts_ms": 1_000, "conn_id": "c1", "peer": "127.0.0.1:50000" },
            { "seq": 2, "ts_ms": 2_100, "conn_id": "c2", "peer": "127.0.0.1:50001" }
        ],
        "messages": [
            { "seq": 3, "ts_ms": 1_100, "conn_id": "c1", "dir": "in",  "len": 300, "sha256": "aa", "verb": "PING", "classified": "ok" },
            { "seq": 4, "ts_ms": 1_900, "conn_id": "c1", "dir": "in",  "len": 500, "sha256": "bb", "verb": null,   "classified": "ok" },
            { "seq": 5, "ts_ms": 1_950, "conn_id": "c1", "dir": "out", "len": 9_999, "sha256": "cc", "verb": null, "classified": "ok" },
            { "seq": 6, "ts_ms": 2_200, "conn_id": "c2", "dir": "in",  "len": 100, "sha256": "dd", "verb": null,   "classified": "trigger" }
        ],
        "closes": [
            { "seq": 7, "ts_ms": 2_300, "conn_id": "c2", "reason": "trigger", "bytes_in": 900, "bytes_out": 9_999 }
        ],
        "downtime": [
            { "seq": 8, "ts_ms": 2_300, "service": "l4-tlv-crash", "conn_id": "c2", "down_at_ms": 2_300, "up_at_ms": 7_300, "trigger_sha256": "dd" }
        ]
    });

    let observed = summarise(&service, 0);

    assert_eq!(observed.accepts, 2);
    assert_eq!(observed.closes, 1);
    assert_eq!(observed.classified["ok"], 3);
    assert_eq!(observed.classified["trigger"], 1);
    assert_eq!(observed.denylisted, 0);
    // The 5 s V-mode crash window.
    assert_eq!(observed.downtime_ms, vec![5_000]);
    // Bucketed by `ts_ms / 1000`, client->server only: the 9 999 B reply is
    // excluded, so the pacer bound is not blamed for the target's own output.
    assert_eq!(observed.windows, BTreeMap::from([(1, 800), (2, 100)]));
    assert_eq!(observed.max_bps, 800);
    assert_eq!(observed.dropped, 0);

    // A service T10 never logged at all is an empty summary, not a panic.
    let empty = summarise(&Value::Null, 4);
    assert_eq!(empty.accepts, 0);
    assert_eq!(empty.denylisted, 0);
    assert_eq!(empty.max_bps, 0);
    assert!(empty.downtime_ms.is_empty());
    assert_eq!(empty.dropped, 4);

    // A denylisted message is counted and surfaced on its own field.
    let denied = summarise(
        &json!({ "messages": [
            { "seq": 1, "ts_ms": 0, "conn_id": "c1", "dir": "in", "len": 10, "sha256": "ee", "verb": "FLUSHALL", "classified": "denylisted" }
        ] }),
        0,
    );
    assert_eq!(denied.denylisted, 1);
}
