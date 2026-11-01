//! The five observe-only HTTP/2 checks (spec D8.2, AC T3-3; T3 plan task 9,
//! amendment A3).
//!
//! No socket is opened. The driver seam is [`RawH2Runner`]; a [`FakeRunner`]
//! records every plan it is handed and answers from a script, so each test can
//! say both what the check *sent* (the plan) and what it *concluded* from a
//! given observation (the verdict).

mod support;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aitm_proto_http::raw_h2::{
    RawH2Mode, RawH2Observation, RawH2Plan, RawH2Target, RawHeader, StreamOutcome,
};
use aitm_scan_checks_http::h2_observe::{h2_checks, RawH2Runner, RealRawH2Runner};
use aitm_scan_model::{
    Check, CheckCost, CheckOrigin, Confidence, InsertionKind, InsertionPoint, Intensity, LaneKind,
    Outcome, ProbeHost, Technique, Verdict,
};
use futures::future::BoxFuture;

use support::{point, ScriptedHost};

const ORIGIN_URL: &str = "https://origin.test/x";

/// The one origin the job's profile names. A raw h2 probe may only be opened
/// to an authority the operator put in the profile, so every host in this file
/// carries it (the off-origin case has its own test).
const ORIGIN: &str = "https://origin.test";

/// The scripted host every test uses: the profile targets [`ORIGIN`].
fn h2host() -> ScriptedHost {
    ScriptedHost::new().with_origins(&[ORIGIN])
}

type Script = dyn Fn(&RawH2Plan) -> anyhow::Result<RawH2Observation> + Send + Sync;

/// Records every plan and answers from a closure.
struct FakeRunner {
    plans: Mutex<Vec<RawH2Plan>>,
    script: Box<Script>,
}

impl FakeRunner {
    fn scripted(
        script: impl Fn(&RawH2Plan) -> anyhow::Result<RawH2Observation> + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            plans: Mutex::new(Vec::new()),
            script: Box::new(script),
        })
    }

    fn answering(obs: RawH2Observation) -> Arc<Self> {
        Self::scripted(move |_| Ok(obs.clone()))
    }

    fn failing() -> Arc<Self> {
        Self::scripted(|_| anyhow::bail!("tls handshake failed: no ALPN h2"))
    }

    fn calls(&self) -> usize {
        self.plans.lock().unwrap().len()
    }

    fn plans(&self) -> Vec<RawH2Plan> {
        self.plans.lock().unwrap().clone()
    }

    fn only_plan(&self) -> RawH2Plan {
        let plans = self.plans();
        assert_eq!(plans.len(), 1, "expected exactly one raw connection");
        plans.into_iter().next().unwrap()
    }
}

impl RawH2Runner for FakeRunner {
    fn run<'a>(&'a self, plan: RawH2Plan) -> BoxFuture<'a, anyhow::Result<RawH2Observation>> {
        Box::pin(async move {
            let out = (self.script)(&plan);
            self.plans.lock().unwrap().push(plan);
            out
        })
    }
}

fn obs(streams: Vec<StreamOutcome>) -> RawH2Observation {
    RawH2Observation {
        settings: vec![(3, 128), (4, 65535)],
        streams,
        goaway: None,
        connection_closed: false,
        elapsed_ms: 5,
    }
}

fn reset() -> StreamOutcome {
    StreamOutcome::Reset { error_code: 1 }
}

fn resets(n: usize) -> RawH2Observation {
    obs(vec![reset(); n])
}

fn check_named(runner: &Arc<FakeRunner>, id: &str) -> Arc<dyn Check> {
    let dynamic: Arc<dyn RawH2Runner> = runner.clone();
    h2_checks(dynamic)
        .into_iter()
        .find(|c| c.meta().id == id)
        .unwrap_or_else(|| panic!("no check named {id}"))
}

fn origin_point() -> InsertionPoint {
    point(InsertionKind::Query, "q", ORIGIN_URL)
}

async fn run(check: &Arc<dyn Check>, host: &ScriptedHost) -> Verdict {
    check.run(&origin_point(), host).await
}

fn blocks(plan: &RawH2Plan) -> &Vec<Vec<RawHeader>> {
    match &plan.mode {
        RawH2Mode::Blocks(b) => b,
        other => panic!("expected Blocks, got {other:?}"),
    }
}

fn h(name: &str, value: &str) -> RawHeader {
    RawHeader::new(name, value)
}

fn base() -> Vec<RawHeader> {
    vec![
        h(":method", "GET"),
        h(":scheme", "https"),
        h(":authority", "origin.test"),
        h(":path", "/x"),
    ]
}

const ALL_IDS: [&str; 5] = [
    "h2-settings-observe",
    "h2-pseudo-header-validation",
    "h2-header-crlf-tolerance",
    "h2-cl-te-downgrade-indicator",
    "h2-rapid-reset-mitigation",
];

// ---------------------------------------------------------------------------
// meta
// ---------------------------------------------------------------------------

#[test]
fn the_five_checks_carry_the_decided_ids_classes_and_shape() {
    let runner = FakeRunner::failing();
    let dynamic: Arc<dyn RawH2Runner> = runner;
    let metas: Vec<_> = h2_checks(dynamic)
        .iter()
        .map(|c| c.meta().clone())
        .collect();

    let got: Vec<(String, String, Option<u32>, aitm_poc::Severity, Technique)> = metas
        .iter()
        .map(|m| {
            (
                m.id.clone(),
                m.class.clone(),
                m.cwe,
                m.severity,
                m.technique,
            )
        })
        .collect();
    use aitm_poc::Severity::{Info, Medium};
    assert_eq!(
        got,
        vec![
            (
                "h2-settings-observe".to_string(),
                "h2-settings".to_string(),
                None,
                Info,
                Technique::Observe
            ),
            (
                "h2-pseudo-header-validation".to_string(),
                "h2-pseudo-header".to_string(),
                Some(444),
                Info,
                Technique::Malformed
            ),
            // A header the origin accepted with a CR or LF in it is what an
            // HTTP/1.1 backend turns into a second request: Medium, not Info.
            (
                "h2-header-crlf-tolerance".to_string(),
                "h2-header-crlf".to_string(),
                Some(113),
                Medium,
                Technique::Malformed
            ),
            (
                "h2-cl-te-downgrade-indicator".to_string(),
                "h2-smuggling-indicator".to_string(),
                Some(444),
                Info,
                Technique::Observe
            ),
            (
                "h2-rapid-reset-mitigation".to_string(),
                "h2-rapid-reset".to_string(),
                Some(400),
                Info,
                Technique::Observe
            ),
        ]
    );
    // Per-kind ceilings and costs (spec D2, spec-review SP-1 and SP-2).
    let shape: Vec<(String, CheckCost, Confidence)> = metas
        .iter()
        .map(|m| (m.id.clone(), m.cost, m.confidence_max))
        .collect();
    assert_eq!(
        shape,
        vec![
            // Observe is never `certain`: it reads what a server advertises,
            // which is not a reflected or handshake proof.
            (
                "h2-settings-observe".to_string(),
                CheckCost::Light,
                Confidence::Firm
            ),
            (
                "h2-pseudo-header-validation".to_string(),
                CheckCost::Light,
                Confidence::Tentative
            ),
            (
                "h2-header-crlf-tolerance".to_string(),
                CheckCost::Light,
                Confidence::Tentative
            ),
            (
                "h2-cl-te-downgrade-indicator".to_string(),
                CheckCost::Light,
                Confidence::Tentative
            ),
            // Eight streams is not a light probe.
            (
                "h2-rapid-reset-mitigation".to_string(),
                CheckCost::Medium,
                Confidence::Firm
            ),
        ]
    );

    for m in &metas {
        assert_eq!(m.lanes, vec![LaneKind::Http], "{}", m.id);
        assert_eq!(
            m.kinds,
            vec![
                InsertionKind::Query,
                InsertionKind::BodyParam,
                InsertionKind::Header,
                InsertionKind::Cookie,
                InsertionKind::PathSegment,
            ],
            "{}",
            m.id
        );
        assert!(m.needs_baseline, "{}", m.id);
        assert!(!m.targets_session, "{}", m.id);
        assert_eq!(m.origin, CheckOrigin::Native, "{}", m.id);
    }
}

#[test]
fn no_h2_check_is_intrusive() {
    let runner = FakeRunner::failing();
    let dynamic: Arc<dyn RawH2Runner> = runner;
    for check in h2_checks(dynamic) {
        assert_eq!(
            check.meta().intensity,
            Intensity::Medium,
            "{}",
            check.meta().id
        );
    }
}

// ---------------------------------------------------------------------------
// h2-settings-observe
// ---------------------------------------------------------------------------

#[tokio::test]
async fn settings_observe_reports_the_advertised_values() {
    let runner = FakeRunner::answering(obs(vec![]));
    let check = check_named(&runner, "h2-settings-observe");
    let host = h2host();

    let v = run(&check, &host).await;

    assert_eq!(v.outcome, Outcome::Vulnerable);
    assert_eq!(v.confidence, Confidence::Firm);
    assert_eq!(check.meta().severity, aitm_poc::Severity::Info);
    assert!(
        v.detail.contains("max_concurrent_streams=128"),
        "{}",
        v.detail
    );
    assert!(
        v.detail.contains("initial_window_size=65535"),
        "{}",
        v.detail
    );
    assert_eq!(
        v.evidence.matched.as_deref(),
        Some("max_concurrent_streams=128, initial_window_size=65535")
    );
    let plan = runner.only_plan();
    assert_eq!(plan.mode, RawH2Mode::SettingsOnly);
    assert_eq!(plan.streams, 0);
    assert_eq!(
        plan.target,
        RawH2Target {
            scheme: "https".to_string(),
            authority: "origin.test".to_string()
        }
    );
}

#[tokio::test]
async fn settings_observe_names_unknown_ids_and_bounds_the_evidence() {
    let mut o = obs(vec![]);
    o.settings = (100u16..160)
        .map(|id| (id, 1_000_000 + u32::from(id)))
        .collect();
    let runner = FakeRunner::answering(o);
    let check = check_named(&runner, "h2-settings-observe");

    let v = run(&check, &h2host()).await;

    let matched = v.evidence.matched.expect("settings listed");
    assert!(
        matched.starts_with("setting_100=1000100, setting_101=1000101"),
        "{matched}"
    );
    assert!(matched.len() <= 256, "{}", matched.len());
}

#[tokio::test]
async fn settings_observe_is_clean_only_when_no_settings_were_read() {
    let mut o = obs(vec![]);
    o.settings = vec![];
    let runner = FakeRunner::answering(o);
    let check = check_named(&runner, "h2-settings-observe");

    let v = run(&check, &h2host()).await;

    assert_eq!(v.outcome, Outcome::Clean);
    assert_eq!(v.confidence, Confidence::Tentative);
    assert_eq!(v.detail, "the peer sent no SETTINGS frame");
}

// ---------------------------------------------------------------------------
// h2-pseudo-header-validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pseudo_header_validation_sends_three_variants_on_one_connection() {
    let runner = FakeRunner::answering(resets(3));
    let check = check_named(&runner, "h2-pseudo-header-validation");

    let v = run(&check, &h2host()).await;

    assert_eq!(v.outcome, Outcome::Clean);
    let plan = runner.only_plan();
    assert_eq!(plan.streams, 3);
    assert!(plan.headers.is_empty());
    assert_eq!(
        blocks(&plan),
        &vec![
            // 0: no :path
            vec![
                h(":method", "GET"),
                h(":scheme", "https"),
                h(":authority", "origin.test"),
            ],
            // 1: :method twice
            vec![
                h(":method", "GET"),
                h(":method", "GET"),
                h(":scheme", "https"),
                h(":authority", "origin.test"),
                h(":path", "/x"),
            ],
            // 2: a pseudo-header after a regular header
            vec![
                h(":method", "GET"),
                h(":scheme", "https"),
                h(":authority", "origin.test"),
                h("x-aitm-probe", "1"),
                h(":path", "/x"),
            ],
        ]
    );
}

#[tokio::test]
async fn pseudo_header_validation_is_clean_when_every_stream_is_reset() {
    let runner = FakeRunner::answering(obs(vec![
        reset(),
        StreamOutcome::Refused,
        StreamOutcome::Headers { status: Some(400) },
    ]));
    let check = check_named(&runner, "h2-pseudo-header-validation");

    let v = run(&check, &h2host()).await;

    assert_eq!(v.outcome, Outcome::Clean);
    assert_eq!(v.evidence.matched, None);
}

/// The plan's name for the case below, kept as its own test so the AC's
/// vocabulary and the suite's agree: a malformed stream the server *answered*
/// is the finding.
#[tokio::test]
async fn pseudo_header_validation_is_vulnerable_when_a_malformed_stream_is_answered() {
    let runner = FakeRunner::answering(obs(vec![
        reset(),
        StreamOutcome::Headers { status: Some(200) },
        reset(),
    ]));
    let check = check_named(&runner, "h2-pseudo-header-validation");

    let v = run(&check, &h2host()).await;

    assert_eq!(v.outcome, Outcome::Vulnerable);
    assert_eq!(v.confidence, Confidence::Tentative);
    assert_eq!(check.meta().severity, aitm_poc::Severity::Info);
}

#[tokio::test]
async fn pseudo_header_validation_names_the_tolerated_variant() {
    let runner = FakeRunner::answering(obs(vec![
        reset(),
        StreamOutcome::Headers { status: Some(200) },
        reset(),
    ]));
    let check = check_named(&runner, "h2-pseudo-header-validation");

    let v = run(&check, &h2host()).await;

    assert_eq!(v.outcome, Outcome::Vulnerable);
    assert_eq!(v.confidence, Confidence::Tentative);
    assert_eq!(
        v.detail,
        "variant 1 (duplicate :method) was answered with status 200 instead of being rejected"
    );
    assert_eq!(
        v.evidence.matched.as_deref(),
        Some("variant 1: duplicate :method")
    );
    assert!(v.poc_hint.is_none());
}

#[tokio::test]
async fn an_answer_with_an_unreadable_status_counts_as_tolerated_and_a_redirect_too() {
    for (answer, expect) in [
        (
            StreamOutcome::Headers { status: None },
            "an unreadable status",
        ),
        (StreamOutcome::Headers { status: Some(302) }, "status 302"),
    ] {
        let runner = FakeRunner::answering(obs(vec![reset(), reset(), answer]));
        let check = check_named(&runner, "h2-pseudo-header-validation");

        let v = run(&check, &h2host()).await;

        assert_eq!(v.outcome, Outcome::Vulnerable, "{answer:?}");
        assert!(
            v.detail
                .starts_with("variant 2 (pseudo-header after a regular header)"),
            "{}",
            v.detail
        );
        assert!(v.detail.contains(expect), "{}", v.detail);
    }
}

#[tokio::test]
async fn a_timed_out_or_missing_stream_is_inconclusive_not_clean() {
    for o in [
        obs(vec![reset(), StreamOutcome::Timeout, reset()]),
        obs(vec![reset(), reset()]),
    ] {
        let runner = FakeRunner::answering(o);
        let check = check_named(&runner, "h2-pseudo-header-validation");

        let v = run(&check, &h2host()).await;

        assert_eq!(v.outcome, Outcome::Inconclusive);
    }
}

// ---------------------------------------------------------------------------
// h2-header-crlf-tolerance
// ---------------------------------------------------------------------------

#[tokio::test]
async fn crlf_tolerance_sends_one_name_and_one_value_probe() {
    let runner = FakeRunner::answering(resets(2));
    let check = check_named(&runner, "h2-header-crlf-tolerance");

    let v = run(&check, &h2host()).await;

    assert_eq!(v.outcome, Outcome::Clean);
    let plan = runner.only_plan();
    assert_eq!(plan.streams, 2);
    let mut value_variant = base();
    value_variant.push(RawHeader::raw(b"x-aitm-probe", b"a\r\nx-aitm-injected: 1"));
    let mut name_variant = base();
    name_variant.push(RawHeader::raw(b"x-aitm-probe\r\nx-aitm-injected", b"1"));
    assert_eq!(blocks(&plan), &vec![value_variant, name_variant]);
}

#[tokio::test]
async fn crlf_tolerance_names_the_tolerated_variant() {
    let runner = FakeRunner::answering(obs(vec![
        reset(),
        StreamOutcome::Headers { status: Some(200) },
    ]));
    let check = check_named(&runner, "h2-header-crlf-tolerance");

    let v = run(&check, &h2host()).await;

    assert_eq!(v.outcome, Outcome::Vulnerable);
    assert_eq!(
        v.detail,
        "variant 1 (CRLF in a header name) was answered with status 200 instead of being rejected"
    );
}

// ---------------------------------------------------------------------------
// h2-cl-te-downgrade-indicator
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cl_te_indicator_sends_two_variants_and_never_a_body() {
    let runner = FakeRunner::answering(resets(2));
    let check = check_named(&runner, "h2-cl-te-downgrade-indicator");

    let v = run(&check, &h2host()).await;

    assert_eq!(v.outcome, Outcome::Clean);
    let plan = runner.only_plan();
    assert_eq!(plan.streams, 2);
    let mut cl = base();
    cl.push(h("content-length", "1"));
    let mut te = base();
    te.push(h("transfer-encoding", "chunked"));
    assert_eq!(blocks(&plan), &vec![cl, te]);
}

#[tokio::test]
async fn cl_te_indicator_is_tentative_when_a_stream_is_answered() {
    let runner = FakeRunner::answering(obs(vec![
        StreamOutcome::Headers { status: Some(200) },
        reset(),
    ]));
    let check = check_named(&runner, "h2-cl-te-downgrade-indicator");

    let v = run(&check, &h2host()).await;

    assert_eq!(v.outcome, Outcome::Vulnerable);
    assert_eq!(v.confidence, Confidence::Tentative);
    assert_eq!(
        v.detail,
        "variant 0 (content-length one byte longer than the body) was answered with status 200 instead of being rejected"
    );
}

// ---------------------------------------------------------------------------
// h2-rapid-reset-mitigation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rapid_reset_never_opens_more_than_eight_pairs() {
    let runner = FakeRunner::answering(resets(8));
    let check = check_named(&runner, "h2-rapid-reset-mitigation");

    run(&check, &h2host()).await;

    let plan = runner.only_plan();
    assert_eq!(plan.mode, RawH2Mode::RapidReset { pairs: 8 });
    assert_eq!(plan.streams, 8);
    assert_eq!(plan.headers, base());
}

#[tokio::test]
async fn rapid_reset_is_clean_when_the_peer_sends_goaway() {
    let mut o = resets(8);
    o.goaway = Some((15, 11));
    let runner = FakeRunner::answering(o);
    let check = check_named(&runner, "h2-rapid-reset-mitigation");

    let v = run(&check, &h2host()).await;

    assert_eq!(v.outcome, Outcome::Clean);
    assert_eq!(
        v.detail,
        "the peer sent GOAWAY(last_stream_id=15, error_code=11) during 8 reset pairs"
    );
}

#[tokio::test]
async fn rapid_reset_is_clean_when_the_peer_refuses_a_stream() {
    let mut streams = vec![reset(); 8];
    streams[5] = StreamOutcome::Refused;
    let runner = FakeRunner::answering(obs(streams));
    let check = check_named(&runner, "h2-rapid-reset-mitigation");

    let v = run(&check, &h2host()).await;

    assert_eq!(v.outcome, Outcome::Clean);
    assert_eq!(v.detail, "the peer refused a stream during 8 reset pairs");
}

#[tokio::test]
async fn rapid_reset_without_goaway_reports_no_mitigation_observed() {
    let runner = FakeRunner::answering(resets(8));
    let check = check_named(&runner, "h2-rapid-reset-mitigation");

    let v = run(&check, &h2host()).await;

    assert_eq!(v.outcome, Outcome::Vulnerable);
    // A complete repeated observation — eight pairs, nothing from the peer —
    // is `firm`, and reaches the meta's ceiling (spec review SP-3).
    assert_eq!(v.confidence, Confidence::Firm);
    assert_eq!(
        v.detail,
        "no reset-rate mitigation observed in 8 reset pairs"
    );
}

// ---------------------------------------------------------------------------
// the scope gate, the once-per-authority guard, the stop contract
// ---------------------------------------------------------------------------

#[tokio::test]
async fn every_h2_check_calls_baseline_before_it_dials() {
    for id in ALL_IDS {
        let runner = FakeRunner::answering(resets(8));
        let check = check_named(&runner, id);
        let host = h2host().with_baseline_fails(true);

        let v = run(&check, &host).await;

        assert_eq!(v.outcome, Outcome::Inconclusive, "{id}");
        assert_eq!(v.detail, "baseline refused; not probing", "{id}");
        assert_eq!(host.baseline_calls(), 1, "{id}");
        assert_eq!(
            runner.calls(),
            0,
            "{id}: no raw connection after a refused baseline"
        );
    }
}

#[tokio::test]
async fn a_refused_baseline_does_not_use_up_the_authority() {
    let runner = FakeRunner::answering(resets(8));
    let check = check_named(&runner, "h2-rapid-reset-mitigation");

    let refused = run(&check, &h2host().with_baseline_fails(true)).await;
    let allowed = run(&check, &h2host()).await;

    assert_eq!(refused.outcome, Outcome::Inconclusive);
    assert_eq!(allowed.outcome, Outcome::Vulnerable);
    assert_eq!(runner.calls(), 1);
}

#[tokio::test]
async fn an_h2_check_runs_once_per_authority() {
    let runner = FakeRunner::answering(resets(8));
    let check = check_named(&runner, "h2-rapid-reset-mitigation");
    let host = h2host();
    let second_host = h2host();

    let first = run(&check, &host).await;
    let second = check
        .run(
            &point(
                InsertionKind::Header,
                "x-forwarded-for",
                "https://origin.test/other",
            ),
            &second_host,
        )
        .await;

    assert_eq!(first.outcome, Outcome::Vulnerable);
    assert_eq!(second.outcome, Outcome::Inconclusive);
    assert_eq!(second.detail, "already observed for this authority");
    assert_eq!(runner.calls(), 1);
    assert_eq!(
        second_host.baseline_calls(),
        0,
        "a repeat sends nothing at all"
    );
}

#[tokio::test]
async fn the_guard_is_per_authority_and_per_scheme() {
    let runner = FakeRunner::answering(resets(8));
    let check = check_named(&runner, "h2-rapid-reset-mitigation");

    for url in [
        "https://origin.test/x",
        "https://origin.test:8443/x",
        "https://other.test/x",
        "http://origin.test/x",
    ] {
        let host = ScriptedHost::new().with_origins(&[
            "https://origin.test",
            "https://origin.test:8443",
            "https://other.test",
            "http://origin.test",
        ]);
        let v = check
            .run(&point(InsertionKind::Query, "q", url), &host)
            .await;
        assert_eq!(v.outcome, Outcome::Vulnerable, "{url}");
    }

    assert_eq!(runner.calls(), 4);
}

#[tokio::test]
async fn the_guard_is_per_check_instance() {
    let runner = FakeRunner::answering(resets(8));
    let one = check_named(&runner, "h2-rapid-reset-mitigation");
    let two = check_named(&runner, "h2-rapid-reset-mitigation");

    run(&one, &h2host()).await;
    let v = run(&two, &h2host()).await;

    assert_eq!(v.outcome, Outcome::Vulnerable);
    assert_eq!(runner.calls(), 2);
}

#[tokio::test]
async fn each_check_has_its_own_guard() {
    let runner = FakeRunner::scripted(|plan| match &plan.mode {
        RawH2Mode::SettingsOnly => Ok(obs(vec![])),
        _ => Ok(resets(plan.streams as usize)),
    });
    let dynamic: Arc<dyn RawH2Runner> = runner.clone();
    let checks = h2_checks(dynamic);

    for check in &checks {
        let v = run(check, &h2host()).await;
        assert_ne!(v.outcome, Outcome::Inconclusive, "{}", check.meta().id);
    }

    assert_eq!(runner.calls(), 5);
}

#[tokio::test]
async fn a_runner_error_is_inconclusive_for_every_check() {
    for id in ALL_IDS {
        let runner = FakeRunner::failing();
        let check = check_named(&runner, id);

        let v = run(&check, &h2host()).await;

        assert_eq!(v.outcome, Outcome::Inconclusive, "{id}");
        assert_eq!(
            v.detail, "origin does not negotiate h2 (or the raw probe failed)",
            "{id}"
        );
        assert!(v.poc_hint.is_none(), "{id}");
    }
}

#[tokio::test]
async fn a_stopped_job_sends_nothing() {
    for host in [
        h2host().with_cancelled(true),
        h2host().with_budget(0),
        h2host().with_deadline(Instant::now() - Duration::from_secs(1)),
    ] {
        let runner = FakeRunner::answering(resets(8));
        let check = check_named(&runner, "h2-rapid-reset-mitigation");

        let v = run(&check, &host).await;

        assert_eq!(v.outcome, Outcome::Inconclusive);
        assert_eq!(host.baseline_calls(), 0);
        assert_eq!(runner.calls(), 0);
    }
}

/// The raw connection cannot charge the host — `ProbeHost` has no `charge` —
/// so the check refuses to open one the job could not have paid for: the
/// budget left after the baseline must cover the streams the plan will open.
/// A three-stream check on a job with one unit of budget sends nothing.
#[tokio::test]
async fn a_budget_that_cannot_cover_the_streams_opens_no_raw_connection() {
    let runner = FakeRunner::answering(resets(3));
    let check = check_named(&runner, "h2-pseudo-header-validation");
    let host = h2host().with_budget(1);

    let v = run(&check, &host).await;

    assert_eq!(v.outcome, Outcome::Inconclusive);
    assert_eq!(v.detail, "budget too low for the raw probe");
    assert_eq!(runner.calls(), 0);
    // The authority was not claimed, so a job with budget can still probe it.
    let allowed = run(&check, &h2host().with_budget(8)).await;
    assert_eq!(allowed.outcome, Outcome::Clean);
    assert_eq!(runner.calls(), 1);
}

/// What the raw probe does *not* do: spend the host's budget. Nine units are
/// one for the baseline and eight the eight-stream probe must be able to
/// cover; after the probe, eight are still there, because nothing charged for
/// the streams it opened.
#[tokio::test]
async fn the_raw_probe_does_not_spend_the_hosts_budget() {
    let runner = FakeRunner::answering(resets(8));
    let check = check_named(&runner, "h2-rapid-reset-mitigation");
    let host = h2host().with_budget(9);

    let v = run(&check, &host).await;

    assert_eq!(v.outcome, Outcome::Vulnerable);
    assert_eq!(runner.calls(), 1);
    assert_eq!(host.budget_left(), 8, "only the baseline was charged");
}

// ---------------------------------------------------------------------------
// the raw target
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_target_is_derived_from_the_point_url() {
    let cases = [
        ("https://origin.test/x", "https", "origin.test", "/x"),
        (
            "https://origin.test:8443/a/b?q=1#f",
            "https",
            "origin.test:8443",
            "/a/b",
        ),
        ("HTTPS://Origin.TEST", "https", "origin.test", "/"),
        (
            "http://user:secret@origin.test/p",
            "http",
            "origin.test",
            "/p",
        ),
        ("https://[::1]:9443/x", "https", "[::1]:9443", "/x"),
    ];
    for (url, scheme, authority, path) in cases {
        let runner = FakeRunner::answering(resets(8));
        let check = check_named(&runner, "h2-rapid-reset-mitigation");
        let host = ScriptedHost::new().with_origins(&[
            "https://origin.test",
            "https://origin.test:8443",
            "http://origin.test",
            "https://[::1]:9443",
        ]);

        check
            .run(&point(InsertionKind::Query, "q", url), &host)
            .await;

        let plan = runner.only_plan();
        assert_eq!(plan.target.scheme, scheme, "{url}");
        assert_eq!(plan.target.authority, authority, "{url}");
        assert_eq!(plan.headers[1], h(":scheme", scheme), "{url}");
        assert_eq!(plan.headers[2], h(":authority", authority), "{url}");
        assert_eq!(plan.headers[3], h(":path", path), "{url}");
        assert!(
            !format!("{plan:?}").contains("secret"),
            "userinfo must never reach the wire: {url}"
        );
    }
}

#[tokio::test]
async fn an_unusable_url_is_inconclusive_and_dials_nothing() {
    let mut no_url = origin_point();
    no_url.url = None;
    let mut points = vec![no_url];
    for url in [
        "ftp://origin.test/x",
        "https:///x",
        "origin.test/x",
        "https://exa mple.test/",
    ] {
        points.push(point(InsertionKind::Query, "q", url));
    }
    for p in points {
        let runner = FakeRunner::answering(resets(8));
        let check = check_named(&runner, "h2-rapid-reset-mitigation");

        let v = check.run(&p, &h2host()).await;

        assert_eq!(v.outcome, Outcome::Inconclusive, "{:?}", p.url);
        assert_eq!(
            v.detail, "the point has no usable http(s) url",
            "{:?}",
            p.url
        );
        assert_eq!(runner.calls(), 0, "{:?}", p.url);
    }
}

#[tokio::test]
async fn a_path_with_control_bytes_falls_back_to_the_root() {
    let runner = FakeRunner::answering(resets(8));
    let check = check_named(&runner, "h2-rapid-reset-mitigation");

    check
        .run(
            &point(InsertionKind::Query, "q", "https://origin.test/a b"),
            &h2host(),
        )
        .await;

    assert_eq!(runner.only_plan().headers[3], h(":path", "/"));
}

// ---------------------------------------------------------------------------
// the profile-origin gate
// ---------------------------------------------------------------------------

/// A raw h2 probe bypasses the lane's own client, so the only thing standing
/// between it and an unauthorised origin is this check: the authority it is
/// about to dial must be one the profile names. A point that arrived pointing
/// somewhere else — a redirect the crawler followed, a host header the
/// application echoed — opens nothing, and does not even take a baseline.
#[tokio::test]
async fn a_point_outside_the_profile_origins_is_never_dialled() {
    for id in ALL_IDS {
        let runner = FakeRunner::answering(resets(8));
        let check = check_named(&runner, id);
        let host = ScriptedHost::new().with_origins(&["https://origin.test"]);

        let v = check
            .run(
                &point(InsertionKind::Query, "q", "https://other.test/"),
                &host,
            )
            .await;

        assert_eq!(v.outcome, Outcome::Inconclusive, "{id}");
        assert_eq!(v.detail, "raw probe target is not a profile origin", "{id}");
        assert_eq!(runner.calls(), 0, "{id} dialled an origin nobody named");
        assert_eq!(host.baseline_calls(), 0, "{id}");
    }
}

/// An empty origin list names nothing, so it authorises nothing.
#[tokio::test]
async fn an_empty_profile_origin_list_authorises_no_raw_probe() {
    let runner = FakeRunner::answering(resets(8));
    let check = check_named(&runner, "h2-rapid-reset-mitigation");
    let host = ScriptedHost::new();

    let v = run(&check, &host).await;

    assert_eq!(v.outcome, Outcome::Inconclusive);
    assert_eq!(v.detail, "raw probe target is not a profile origin");
    assert_eq!(runner.calls(), 0);
    assert_eq!(host.baseline_calls(), 0);
}

/// Scheme and port are part of an origin: `http://origin.test` does not
/// authorise an `https` probe, and `https://origin.test:8443` does not
/// authorise the default port.
#[tokio::test]
async fn the_origin_gate_is_per_scheme_and_per_port() {
    for (origin, url) in [
        ("http://origin.test", "https://origin.test/x"),
        ("https://origin.test:8443", "https://origin.test/x"),
        ("https://origin.test", "https://origin.test:8443/x"),
        ("origin.test", "https://origin.test/x"),
    ] {
        let runner = FakeRunner::answering(resets(8));
        let check = check_named(&runner, "h2-rapid-reset-mitigation");
        let host = ScriptedHost::new().with_origins(&[origin]);

        let v = check
            .run(&point(InsertionKind::Query, "q", url), &host)
            .await;

        assert_eq!(v.outcome, Outcome::Inconclusive, "{origin} vs {url}");
        assert_eq!(v.detail, "raw probe target is not a profile origin");
        assert_eq!(runner.calls(), 0, "{origin} vs {url}");
    }
}

/// The comparison and the guard key both run on a **normalised** authority:
/// the host is lower-cased and the scheme's default port is filled in, so
/// `origin.test` and `origin.test:443` are one origin for an `https` job.
/// Two points that differ only that way therefore share one claim, and the
/// probe is opened once.
#[tokio::test]
async fn the_default_port_is_the_same_origin_and_the_same_guard_claim() {
    let runner = FakeRunner::answering(resets(8));
    let check = check_named(&runner, "h2-rapid-reset-mitigation");

    let first = check
        .run(
            &point(InsertionKind::Query, "q", "https://origin.test/a"),
            &ScriptedHost::new().with_origins(&["https://origin.test"]),
        )
        .await;
    let second = check
        .run(
            &point(InsertionKind::Query, "q", "https://ORIGIN.test:443/b"),
            &ScriptedHost::new().with_origins(&["https://origin.test"]),
        )
        .await;

    assert_eq!(first.outcome, Outcome::Vulnerable);
    assert_eq!(second.outcome, Outcome::Inconclusive);
    assert_eq!(second.detail, "already observed for this authority");
    assert_eq!(runner.calls(), 1, "one authority, one raw connection");
}

/// The same normalisation on the profile's side: an origin written without a
/// port authorises a point written with the scheme's default port, and an
/// origin written with the default port authorises one written without it.
#[tokio::test]
async fn a_profile_origin_matches_a_point_however_the_default_port_is_written() {
    for (origin, url) in [
        ("https://origin.test", "https://origin.test:443/x"),
        ("https://origin.test:443", "https://origin.test/x"),
        ("https://ORIGIN.test", "https://origin.test/x"),
        ("http://origin.test:80", "http://origin.test/x"),
    ] {
        let runner = FakeRunner::answering(resets(8));
        let check = check_named(&runner, "h2-rapid-reset-mitigation");
        let host = ScriptedHost::new().with_origins(&[origin]);

        let v = check
            .run(&point(InsertionKind::Query, "q", url), &host)
            .await;

        assert_eq!(v.outcome, Outcome::Vulnerable, "{origin} vs {url}");
        assert_eq!(runner.calls(), 1, "{origin} vs {url}");
    }
}

// ---------------------------------------------------------------------------
// the AC T3-3 expected set, and the standing guarantees
// ---------------------------------------------------------------------------

/// A conforming (hyper-like) server: advertises SETTINGS, resets every
/// malformed stream with PROTOCOL_ERROR and every cancelled stream, and never
/// sends GOAWAY.
fn conforming_runner() -> Arc<FakeRunner> {
    FakeRunner::scripted(|plan| {
        let mut o = match &plan.mode {
            RawH2Mode::SettingsOnly => obs(vec![]),
            _ => resets(plan.streams as usize),
        };
        o.settings = vec![(3, 100), (4, 65535)];
        Ok(o)
    })
}

#[tokio::test]
async fn the_t3_3_expected_set_on_a_conforming_server() {
    let runner = conforming_runner();
    let dynamic: Arc<dyn RawH2Runner> = runner.clone();
    let mut got = Vec::new();
    for check in h2_checks(dynamic) {
        let v = run(&check, &h2host()).await;
        got.push((check.meta().id.clone(), v.outcome, check.meta().severity));
    }

    use aitm_poc::Severity::Info;
    assert_eq!(
        got,
        vec![
            ("h2-settings-observe".to_string(), Outcome::Vulnerable, Info),
            (
                "h2-pseudo-header-validation".to_string(),
                Outcome::Clean,
                Info
            ),
            (
                "h2-header-crlf-tolerance".to_string(),
                Outcome::Clean,
                aitm_poc::Severity::Medium
            ),
            (
                "h2-cl-te-downgrade-indicator".to_string(),
                Outcome::Clean,
                Info
            ),
            (
                "h2-rapid-reset-mitigation".to_string(),
                Outcome::Vulnerable,
                Info
            ),
        ]
    );
    // One connection per check, never more.
    assert_eq!(runner.calls(), 5);
}

#[tokio::test]
async fn no_plan_ever_exceeds_eight_streams_or_carries_session_material() {
    let runner = conforming_runner();
    let dynamic: Arc<dyn RawH2Runner> = runner.clone();
    for check in h2_checks(dynamic) {
        run(&check, &h2host()).await;
    }

    for plan in runner.plans() {
        assert!(plan.streams <= 8, "{plan:?}");
        let opened = match &plan.mode {
            RawH2Mode::SettingsOnly => 0,
            RawH2Mode::SingleRequest => 1,
            RawH2Mode::RapidReset { pairs } => usize::from(*pairs),
            RawH2Mode::Blocks(b) => b.len(),
        };
        assert_eq!(usize::from(plan.streams), opened, "{plan:?}");
        let all: Vec<&RawHeader> = match &plan.mode {
            RawH2Mode::Blocks(b) => b.iter().flatten().collect(),
            _ => plan.headers.iter().collect(),
        };
        for header in all {
            let name = String::from_utf8_lossy(&header.name).to_ascii_lowercase();
            for forbidden in [
                "cookie",
                "authorization",
                "proxy-authorization",
                "set-cookie",
            ] {
                assert_ne!(name, forbidden, "{plan:?}");
            }
        }
    }
}

#[tokio::test]
async fn no_h2_check_supplies_a_poc_hint() {
    let vulnerable = FakeRunner::answering(obs(vec![
        StreamOutcome::Headers { status: Some(200) },
        StreamOutcome::Headers { status: Some(200) },
        StreamOutcome::Headers { status: Some(200) },
    ]));
    for id in ALL_IDS {
        let check = check_named(&vulnerable, id);
        let v = run(&check, &h2host()).await;
        assert!(v.poc_hint.is_none(), "{id}");
    }
    assert!(vulnerable.calls() > 0);
}

#[tokio::test]
async fn the_real_runner_refuses_session_material_before_dialling() {
    let runner = RealRawH2Runner::new();
    let plan = RawH2Plan {
        target: RawH2Target {
            scheme: "https".to_string(),
            authority: "origin.test".to_string(),
        },
        headers: vec![h(":method", "GET"), h("cookie", "sid=1")],
        mode: RawH2Mode::SingleRequest,
        streams: 1,
    };

    let err = runner
        .run(plan)
        .await
        .expect_err("a cookie header is refused");

    assert_eq!(
        err.to_string(),
        "a raw h2 probe never sends a `cookie` header"
    );
}

/// Every one of the five, not just the rapid-reset one: a point whose URL is
/// missing, non-http(s) or unparseable opens no connection at all. The raw
/// driver's whole safety argument (module doc, condition 1) is that it dials
/// the point's own authority, so a check that guessed a target when the point
/// named none would be dialling somewhere nobody authorised.
#[tokio::test]
async fn no_h2_check_dials_without_a_usable_http_url() {
    let mut no_url = origin_point();
    no_url.url = None;
    let mut points = vec![no_url];
    for url in [
        "ftp://origin.test/x",
        "file:///etc/passwd",
        "wss://origin.test/ws",
        "https:///x",
        "origin.test/x",
        "",
    ] {
        points.push(point(InsertionKind::Query, "q", url));
    }

    for id in ALL_IDS {
        for p in &points {
            let runner = FakeRunner::answering(resets(8));
            let check = check_named(&runner, id);
            let host = h2host();

            let v = check.run(p, &host).await;

            assert_eq!(v.outcome, Outcome::Inconclusive, "{id} {:?}", p.url);
            assert_eq!(v.detail, "the point has no usable http(s) url");
            assert_eq!(runner.calls(), 0, "{id} dialled for {:?}", p.url);
            assert_eq!(
                host.baseline_calls(),
                0,
                "{id} probed the lane for {:?}",
                p.url
            );
        }
    }
}

/// The stop contract for all five: a cancelled job, a job with no budget and a
/// job past its deadline each send nothing — no baseline, no raw connection —
/// and the authority is left unclaimed, so the check can still run when a later
/// job reaches the same origin.
#[tokio::test]
async fn no_h2_check_probes_a_stopped_job_or_burns_the_authority() {
    for id in ALL_IDS {
        for stopped in [
            h2host().with_cancelled(true),
            h2host().with_budget(0),
            h2host().with_deadline(Instant::now() - Duration::from_secs(1)),
        ] {
            let runner = FakeRunner::answering(resets(8));
            let check = check_named(&runner, id);

            let v = run(&check, &stopped).await;

            assert_eq!(v.outcome, Outcome::Inconclusive, "{id}");
            assert_eq!(
                v.detail,
                "stopped: the job was cancelled, out of budget or past its deadline"
            );
            assert_eq!(stopped.baseline_calls(), 0, "{id}");
            assert_eq!(runner.calls(), 0, "{id}");

            // The authority was never claimed, so a healthy run still probes.
            let healthy = run(&check, &h2host()).await;
            assert_ne!(healthy.outcome, Outcome::Inconclusive, "{id}");
            assert_eq!(runner.calls(), 1, "{id}");
        }
    }
}
