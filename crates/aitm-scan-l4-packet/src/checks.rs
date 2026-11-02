//! The two packet-lane checks, `l4-packet-crash` and `l4-packet-reaction` —
//! owned by scanner v2 track T5, plan task 10.
//!
//! Neither check sends: both read the one cached [`crate::state::PointRun`] of
//! the point they were handed, found through the
//! [`RunnerRegistry`](crate::host::RunnerRegistry) by `(job marker, point id)`,
//! so whichever check reaches a point first drives its cases and the other
//! renders a verdict over the same run (spec D8.4, plan call C2).
//!
//! The crash check is the lane's `critical`, `firm` `l4-crash` issue: a case
//! after which both liveness probes failed, with the bounded
//! reproduce-then-retire triage recorded in `L4Evidence.reproduced`. The
//! reaction check is `info`: an ICMP error or a TCP reset is the target
//! answering, so it is a protocol reaction and never a crash.

use std::sync::Arc;
use std::time::Duration;

use aitm_scan_model::{
    Check, CheckCost, CheckMeta, CheckOrigin, Confidence, Evidence, InsertionKind, InsertionPoint,
    Intensity, L4Evidence, LaneKind, Outcome, ProbeHost, Technique, Verdict,
};
use futures::future::BoxFuture;

use crate::codec::truncate_hex;
use crate::host::{PointRunner, RunnerRegistry};
use crate::state::{Candidate, CrashRecord, PointRun};

/// The crash check's catalogue id.
pub const CRASH_CHECK_ID: &str = "l4-packet-crash";
/// The reaction check's catalogue id.
pub const REACTION_CHECK_ID: &str = "l4-packet-reaction";
/// The vulnerability class a crash verdict carries.
pub const CRASH_CLASS: &str = "l4-crash";
/// The vulnerability class a reaction verdict carries.
pub const REACTION_CLASS: &str = "l4-protocol-reaction";

/// The crash check's catalogue entry (spec D8.4: `l4-crash`, `critical`,
/// `firm`).
#[must_use]
pub fn crash_meta() -> CheckMeta {
    CheckMeta {
        id: CRASH_CHECK_ID.to_string(),
        name: "L4 packet crash (liveness failed)".to_string(),
        class: CRASH_CLASS.to_string(),
        lanes: vec![LaneKind::L4Packet],
        kinds: vec![InsertionKind::L4Field],
        intensity: Intensity::Intrusive,
        cost: CheckCost::Heavy,
        technique: Technique::Malformed,
        scope: aitm_scan_model::CheckScope::Point,
        severity: aitm_poc::Severity::Critical,
        confidence_max: Confidence::Firm,
        needs_baseline: true,
        wants_traits: None,
        targets_session: false,
        cwe: Some(20),
        description: "A malformed packet field stops the target answering: the two liveness \
                      probes that followed the case both failed."
            .to_string(),
        remediation: Some(
            "Validate every header field and payload length before use, and bound what one \
             datagram can allocate or loop over."
                .to_string(),
        ),
        origin: CheckOrigin::Native,
    }
}

/// The reaction check's catalogue entry (spec D8.4: an ICMP error or a reset
/// is `info`, with the type and code in `L4Evidence.oracle`).
#[must_use]
pub fn reaction_meta() -> CheckMeta {
    CheckMeta {
        id: REACTION_CHECK_ID.to_string(),
        name: "L4 packet protocol reaction".to_string(),
        class: REACTION_CLASS.to_string(),
        lanes: vec![LaneKind::L4Packet],
        kinds: vec![InsertionKind::L4Field],
        intensity: Intensity::Intrusive,
        cost: CheckCost::Heavy,
        technique: Technique::Observe,
        scope: aitm_scan_model::CheckScope::Point,
        severity: aitm_poc::Severity::Info,
        confidence_max: Confidence::Firm,
        needs_baseline: true,
        wants_traits: None,
        targets_session: false,
        cwe: None,
        description: "The target answered a malformed packet with a protocol-level reaction: an \
                      ICMP error or a TCP reset, recorded with its type and code."
            .to_string(),
        remediation: None,
        origin: CheckOrigin::Native,
    }
}

/// The two native checks of the packet lane, in catalogue order.
///
/// Both share the lane's one registry, so either may be the check that drives
/// a point's cases.
#[must_use]
pub fn checks(registry: Arc<RunnerRegistry>) -> Vec<Arc<dyn Check>> {
    vec![
        Arc::new(CrashCheck::new(Arc::clone(&registry))),
        Arc::new(ReactionCheck::new(registry)),
    ]
}

/// The `l4-packet-crash` check: a case after which the target stopped
/// answering.
#[derive(Debug)]
pub struct CrashCheck {
    registry: Arc<RunnerRegistry>,
    meta: CheckMeta,
}

impl CrashCheck {
    /// A crash check over the lane's runner registry.
    #[must_use]
    pub fn new(registry: Arc<RunnerRegistry>) -> Self {
        Self {
            registry,
            meta: crash_meta(),
        }
    }
}

impl Check for CrashCheck {
    fn meta(&self) -> &CheckMeta {
        &self.meta
    }

    fn run<'a>(
        &'a self,
        point: &'a InsertionPoint,
        host: &'a dyn ProbeHost,
    ) -> BoxFuture<'a, Verdict> {
        Box::pin(async move {
            let (_runner, run) = match resolve_run(&self.registry, point, host).await {
                Ok(pair) => pair,
                Err(verdict) => return verdict,
            };
            if let Some(crash) = run.crash.as_ref() {
                return crash_verdict(&run, crash);
            }
            if run.dry_run {
                return dry_run_verdict(&run);
            }
            if let Some(verdict) = candidate_verdict(&run) {
                return verdict;
            }
            if let Some(verdict) = stopped_verdict(&run) {
                return verdict;
            }
            Verdict {
                outcome: Outcome::Clean,
                confidence: Confidence::Firm,
                evidence: Evidence::default(),
                detail: format!(
                    "{} cases sent on {} field {}; no crash",
                    run.sent_count(),
                    run.target,
                    run.field
                ),
                poc_hint: None,
                location: None,
                more: Vec::new(),
            }
        })
    }
}

/// The `l4-packet-reaction` check: the ICMP errors and resets a point's cases
/// drew out of the target.
#[derive(Debug)]
pub struct ReactionCheck {
    registry: Arc<RunnerRegistry>,
    meta: CheckMeta,
}

impl ReactionCheck {
    /// A reaction check over the lane's runner registry.
    #[must_use]
    pub fn new(registry: Arc<RunnerRegistry>) -> Self {
        Self {
            registry,
            meta: reaction_meta(),
        }
    }
}

impl Check for ReactionCheck {
    fn meta(&self) -> &CheckMeta {
        &self.meta
    }

    fn run<'a>(
        &'a self,
        point: &'a InsertionPoint,
        host: &'a dyn ProbeHost,
    ) -> BoxFuture<'a, Verdict> {
        Box::pin(async move {
            let (runner, run) = match resolve_run(&self.registry, point, host).await {
                Ok(pair) => pair,
                Err(verdict) => return verdict,
            };
            if run.dry_run {
                return dry_run_verdict(&run);
            }
            if let Some(verdict) = stopped_verdict(&run) {
                return verdict;
            }
            reaction_verdict(&run, runner.scope_entry())
        })
    }
}

/// The preamble both checks share: find the point's one runner through the
/// registry and drive (or read) its cached run (review finding M8).
///
/// `Err` carries the [`missing_runner`] verdict for a point whose runner was
/// never registered, so a caller returns it directly.
async fn resolve_run(
    registry: &RunnerRegistry,
    point: &InsertionPoint,
    host: &dyn ProbeHost,
) -> Result<(Arc<PointRunner>, Arc<PointRun>), Verdict> {
    let Some(runner) = registry.get(&host.marker(), &point.id) else {
        return Err(missing_runner(&point.id));
    };
    let run = runner.run_point().await;
    Ok((runner, run))
}

/// The verdict for a point whose runner was never registered: the engine
/// called a check before the lane built the point's host.
fn missing_runner(point_id: &str) -> Verdict {
    Verdict {
        outcome: Outcome::Error,
        confidence: Confidence::Tentative,
        location: None,
        more: Vec::new(),
        evidence: Evidence::default(),
        detail: format!(
            "no packet-lane runner registered for point {point_id}; probe_host_for must run first"
        ),
        poc_hint: None,
    }
}

/// The crash verdict: `vulnerable`/`firm`, with the triggering case's own
/// `L4Evidence` carried through unchanged.
fn crash_verdict(run: &PointRun, crash: &CrashRecord) -> Verdict {
    let matched = if crash.recovered {
        format!(
            "liveness failed after case; reproduced {}/{}",
            crash.evidence.reproduced.0, crash.evidence.reproduced.1
        )
    } else {
        format!(
            "liveness failed after case; target did not recover within {}",
            human_wait(run.recovery_wait)
        )
    };
    Verdict {
        outcome: Outcome::Vulnerable,
        confidence: Confidence::Firm,
        location: None,
        more: Vec::new(),
        evidence: Evidence {
            payload: Some(crash.evidence.sent_hex.clone()),
            matched: Some(matched),
            probe_flows: Vec::new(),
            baseline_flow: None,
            timing: None,
            diff: None,
            l4: Some(crash.evidence.clone()),
        },
        detail: crash_detail(run, crash),
        poc_hint: None,
    }
}

/// The reaction verdict: `vulnerable`/`firm` at `info` severity when the run
/// saw at least one ICMP error or reset, else clean.
fn reaction_verdict(run: &PointRun, scope_entry: &str) -> Verdict {
    let clean = || Verdict {
        outcome: Outcome::Clean,
        confidence: Confidence::Firm,
        location: None,
        more: Vec::new(),
        evidence: Evidence::default(),
        detail: format!(
            "{} cases sent on {} field {}; no protocol reaction",
            run.sent_count(),
            run.target,
            run.field
        ),
        poc_hint: None,
    };
    let Some(&(class, count)) = run.reactions().first() else {
        return clean();
    };
    let Some(oracle) = class.oracle() else {
        return clean();
    };
    let Some(case) = run.cases.iter().find(|case| case.class() == Some(class)) else {
        return clean();
    };
    let evidence = L4Evidence {
        sent_hex: case.sent_hex.clone(),
        seed_id: case.seed_id.clone(),
        rng_seed: run.rng_seed,
        mutation_chain: case.chain.clone(),
        prior_messages: 0,
        oracle,
        // The target answered, so it was alive on both sides of the case.
        liveness_before: true,
        liveness_after: true,
        reproduced: (count, count),
        scope_entry: scope_entry.to_string(),
    };
    Verdict {
        outcome: Outcome::Vulnerable,
        confidence: Confidence::Firm,
        location: None,
        more: Vec::new(),
        evidence: Evidence {
            payload: Some(evidence.sent_hex.clone()),
            matched: Some(format!("{} x {count}", class.label())),
            probe_flows: Vec::new(),
            baseline_flow: None,
            timing: None,
            diff: None,
            l4: Some(evidence),
        },
        detail: reaction_detail(run),
        poc_hint: None,
    }
}

/// The verdict for a dry run: nothing was sent, so nothing is concluded.
fn dry_run_verdict(run: &PointRun) -> Verdict {
    Verdict {
        outcome: Outcome::Clean,
        confidence: Confidence::Firm,
        location: None,
        more: Vec::new(),
        evidence: Evidence {
            payload: run.cases.first().map(|case| case.sent_hex.clone()),
            ..Evidence::default()
        },
        detail: dry_run_detail(run),
        poc_hint: None,
    }
}

/// The verdict for a candidate the triage never answered: the case left the
/// target silent on both liveness probes, but no replay ever judged it, so the
/// point is neither clean nor crashed — `inconclusive`/`tentative`, saying why
/// (tester finding F1, review finding G1).
///
/// Read off the cases themselves, never inferred from the run's stop: a
/// triage that ran and did not reproduce its candidate
/// ([`Candidate::NotReproduced`]) is the lane's answer, and a stop afterwards
/// does not reopen it (review finding Q2). The candidate carried is the most
/// recent unanswered one, which is the case an interrupted triage was
/// reproducing. `Evidence.l4` stays `None`: an `L4Evidence` asserts a
/// reproduction count, and nothing was reproduced.
///
/// `None` when every candidate of the run was answered, or there was none.
/// The caller has already returned for a run that holds a crash.
fn candidate_verdict(run: &PointRun) -> Option<Verdict> {
    let (case, why) = run
        .cases
        .iter()
        .rev()
        .find_map(|case| match &case.candidate {
            Candidate::Interrupted { stop, .. } => {
                Some((case, format!("{stop} before reproduction")))
            }
            Candidate::Unjudged => {
                Some((case, "not reproduced (reproduce_count is 0)".to_string()))
            }
            Candidate::No | Candidate::NotReproduced { .. } | Candidate::Confirmed { .. } => None,
        })?;
    Some(Verdict {
        outcome: Outcome::Inconclusive,
        confidence: Confidence::Tentative,
        location: None,
        more: Vec::new(),
        evidence: Evidence {
            payload: Some(case.sent_hex.clone()),
            ..Evidence::default()
        },
        detail: format!(
            "crash candidate on {} field {} mutation {}: {why}",
            run.target,
            run.field,
            case.chain.join(";")
        ),
        poc_hint: None,
    })
}

/// The verdict for a run the stop ladder ended before any case went out:
/// `error`/`tentative`, naming the stop reason. `None` when the run has cases
/// to judge.
fn stopped_verdict(run: &PointRun) -> Option<Verdict> {
    let reason = run.stopped.as_ref().filter(|_| run.cases.is_empty())?;
    Some(Verdict {
        outcome: Outcome::Error,
        confidence: Confidence::Tentative,
        location: None,
        more: Vec::new(),
        evidence: Evidence::default(),
        detail: format!(
            "the packet lane stopped before any case on {} field {}: {reason}",
            run.target, run.field
        ),
        poc_hint: None,
    })
}

/// The operator-facing line for a crash: what crashed it, how often it
/// reproduced and what the liveness probes said.
#[must_use]
pub fn crash_detail(run: &PointRun, crash: &CrashRecord) -> String {
    let outage = if crash.recovered {
        String::new()
    } else {
        format!(
            "; target did not recover within {}",
            human_wait(run.recovery_wait)
        )
    };
    format!(
        "l4 crash on {} field {} mutation {}; reproduced {}/{}; liveness before {}, after {}{outage}",
        run.target,
        run.field,
        crash.evidence.mutation_chain.join(";"),
        crash.evidence.reproduced.0,
        crash.evidence.reproduced.1,
        crash.evidence.liveness_before,
        crash.evidence.liveness_after,
    )
}

/// The operator-facing line for a run's protocol reactions: one `<label> x
/// <n>` per class in first-seen order, then the latency outliers.
#[must_use]
pub fn reaction_detail(run: &PointRun) -> String {
    let counts = run
        .reactions()
        .iter()
        .map(|(class, count)| format!("{} x {count}", class.label()))
        .collect::<Vec<_>>()
        .join("; ");
    format!(
        "l4 reactions on {} field {}: {counts}; latency outliers {}",
        run.target,
        run.field,
        run.outlier_count()
    )
}

/// The operator-facing line for a dry run: how many cases were rendered and
/// what the first one would have put on the wire.
#[must_use]
pub fn dry_run_detail(run: &PointRun) -> String {
    let first = run
        .cases
        .first()
        .map_or(String::new(), |case| truncate_hex(&case.sent_hex));
    format!(
        "dry run: {} cases rendered for {}; first {first}",
        run.cases.len(),
        run.field
    )
}

/// A recovery wait as the operator reads it: `10s` for whole seconds, else
/// milliseconds.
fn human_wait(wait: Duration) -> String {
    if wait.subsec_millis() == 0 {
        format!("{}s", wait.as_secs())
    } else {
        format!("{}ms", wait.as_millis())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use aitm_scan_model::{
        Check, CheckOrigin, Confidence, InsertionKind, Intensity, JobCtx, L4Oracle, LaneKind,
        Outcome, Technique, Verdict,
    };

    use super::{checks, crash_meta, reaction_meta, CrashCheck, ReactionCheck};
    use crate::codec::hex_encode;
    use crate::fields::FieldPath;
    use crate::host::{PacketHost, PointRunner, RunnerRegistry};
    use crate::oracle::CaseClass;
    use crate::state::{Candidate, StopReason};
    use crate::testing::harness::{runner_for, setup};
    use crate::testing::{
        fields, l4_profile, tcp_target, udp_target, with_hex_seed, MockBackend, MockReply, TestJob,
    };

    /// A registry holding the one runner of the point under test, the way
    /// `Lane::probe_host_for` registers it before a check ever runs.
    fn registry_with(job: &Arc<TestJob>, runner: &Arc<PointRunner>) -> Arc<RunnerRegistry> {
        let registry = Arc::new(RunnerRegistry::new());
        registry.register(
            &job.marker(),
            runner.point().id.as_str(),
            Arc::clone(runner),
        );
        registry
    }

    /// Run one check over the point its runner owns, through the lane's own
    /// `ProbeHost`, as the engine does.
    async fn run_check(check: &dyn Check, runner: &Arc<PointRunner>) -> Verdict {
        let host = PacketHost::new(Arc::clone(runner));
        let point = runner.point().clone();
        check.run(&point, &host).await
    }

    #[test]
    fn metas_match_the_spec() {
        let crash = crash_meta();
        assert_eq!(crash.id, "l4-packet-crash");
        assert_eq!(crash.class, "l4-crash");
        assert_eq!(crash.severity, aitm_poc::Severity::Critical);
        assert_eq!(crash.intensity, Intensity::Intrusive);
        assert_eq!(crash.technique, Technique::Malformed);
        assert_eq!(crash.confidence_max, Confidence::Firm);
        assert_eq!(crash.lanes, vec![LaneKind::L4Packet]);
        assert_eq!(crash.kinds, vec![InsertionKind::L4Field]);
        assert_eq!(crash.origin, CheckOrigin::Native);
        assert!(crash.needs_baseline);
        assert_eq!(crash.cwe, Some(20));
        assert!(crash.remediation.is_some());

        let reaction = reaction_meta();
        assert_eq!(reaction.id, "l4-packet-reaction");
        assert_eq!(reaction.class, "l4-protocol-reaction");
        assert_eq!(reaction.severity, aitm_poc::Severity::Info);
        assert_eq!(reaction.technique, Technique::Observe);
        assert_eq!(reaction.cwe, None);
        assert_eq!(reaction.remediation, None);

        let registry = Arc::new(RunnerRegistry::new());
        let both = checks(registry);
        assert_eq!(both.len(), 2);
        assert_eq!(both[0].meta().id, "l4-packet-crash");
        assert_eq!(both[1].meta().id, "l4-packet-reaction");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn crash_check_reports_vulnerable_firm() {
        let mock = MockBackend::new(MockReply::Echo);
        mock.dies_on_pattern(vec![0xde, 0xad, 0xbe, 0xef], 8, 2, true);
        let profile = with_hex_seed(l4_profile(vec![udp_target(9)], 50), "deadbeef0000");
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");
        let registry = registry_with(&job, &runner);

        let verdict = run_check(&CrashCheck::new(Arc::clone(&registry)), &runner).await;

        assert_eq!(verdict.outcome, Outcome::Vulnerable);
        assert_eq!(verdict.confidence, Confidence::Firm);
        let l4 = verdict.evidence.l4.as_ref().expect("the crash evidence");
        assert_eq!(l4.reproduced, (3, 3));
        assert_eq!(l4.oracle, L4Oracle::LivenessFailed);
        let trigger = mock.injected().get(2).cloned().expect("the third inject");
        assert_eq!(verdict.evidence.payload, Some(hex_encode(&trigger)));
        assert!(verdict.evidence.probe_flows.is_empty());
        assert!(
            verdict.detail.contains("127.0.0.1:9/udp"),
            "detail names the target: {}",
            verdict.detail
        );
        assert!(
            verdict.detail.contains("grow:8"),
            "detail names the mutation: {}",
            verdict.detail
        );
        assert!(
            verdict.detail.contains("reproduced 3/3"),
            "detail reports the replays: {}",
            verdict.detail
        );
        assert!(
            !verdict.detail.contains("did not recover"),
            "the target came back: {}",
            verdict.detail
        );

        // The reaction check reads the same cached run: nothing new goes out.
        let reaction = run_check(&ReactionCheck::new(Arc::clone(&registry)), &runner).await;
        assert_eq!(reaction.outcome, Outcome::Clean);
        assert_eq!(mock.inject_count(), 17);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn persistent_outage_is_still_vulnerable() {
        let mock = MockBackend::new(MockReply::Echo);
        mock.dies_after_injects(6);
        let profile = l4_profile(vec![udp_target(9)], 50);
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");
        let registry = registry_with(&job, &runner);

        let verdict = run_check(&CrashCheck::new(registry), &runner).await;

        assert_eq!(verdict.outcome, Outcome::Vulnerable);
        assert_eq!(verdict.confidence, Confidence::Firm);
        let l4 = verdict.evidence.l4.as_ref().expect("the crash evidence");
        assert_eq!(l4.reproduced, (0, 0));
        assert!(!l4.liveness_after);
        assert!(
            verdict.detail.contains("target did not recover within"),
            "detail reports the persistent outage: {}",
            verdict.detail
        );
        assert_eq!(mock.inject_count(), 19);
    }

    /// Tester finding F1: a triage the stop ladder cut short leaves an
    /// unconfirmed candidate. The run has no crash, so the check must say so
    /// — `inconclusive`/`tentative`, with the candidate's bytes but no
    /// `L4Evidence`, because nothing was reproduced.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn interrupted_triage_is_inconclusive_not_vulnerable() {
        let mock = MockBackend::new(MockReply::Echo);
        mock.dies_on_pattern(vec![0xde, 0xad, 0xbe, 0xef], 8, 2, true);
        let profile = with_hex_seed(l4_profile(vec![udp_target(9)], 50), "deadbeef0000");
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        // 1 baseline + 2 cases + the 2 failed probes = 5; the first recovery
        // poll is the charge that fails, mid-triage.
        let job = job.with_budget(5);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");
        let registry = registry_with(&job, &runner);

        let verdict = run_check(&CrashCheck::new(registry), &runner).await;

        assert_eq!(verdict.outcome, Outcome::Inconclusive);
        assert_eq!(verdict.confidence, Confidence::Tentative);
        let trigger = mock.injected().get(2).cloned().expect("the third inject");
        assert_eq!(verdict.evidence.payload, Some(hex_encode(&trigger)));
        assert!(
            verdict.evidence.l4.is_none(),
            "nothing was reproduced, so there is no crash evidence: {:?}",
            verdict.evidence.l4
        );
        assert_eq!(
            verdict.detail,
            "crash candidate on 127.0.0.1:9/udp field raw mutation grow:8: \
             budget exhausted before reproduction"
        );
        assert!(verdict.detail.contains("crash candidate"));
        assert!(verdict.detail.contains("budget"));
        assert_eq!(
            shared
                .state
                .counters(job.job_id())
                .expect("counters")
                .crashes,
            0
        );
    }

    /// Review finding G1: with `reproduce_count: 0` the triage never runs, so
    /// the candidate stays unconfirmed and the run carries no crash **and no
    /// stop** — the fuzz loop ran to its last case. The check must still
    /// surface the candidate: `inconclusive`/`tentative`, saying why nothing
    /// was reproduced.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unconfirmed_candidate_without_stop_is_inconclusive() {
        let mock = MockBackend::new(MockReply::Echo);
        mock.dies_on_pattern(vec![0xde, 0xad, 0xbe, 0xef], 8, 2, true);
        let mut profile = with_hex_seed(l4_profile(vec![udp_target(9)], 10), "deadbeef0000");
        profile.l4.reproduce_count = 0;
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");
        let registry = registry_with(&job, &runner);

        let verdict = run_check(&CrashCheck::new(registry), &runner).await;

        assert_eq!(verdict.outcome, Outcome::Inconclusive);
        assert_eq!(verdict.confidence, Confidence::Tentative);
        assert!(
            verdict.evidence.l4.is_none(),
            "nothing was reproduced, so there is no crash evidence: {:?}",
            verdict.evidence.l4
        );
        // Eight cases were left unconfirmed; the verdict carries the most
        // recent of them, bytes and mutation chain alike.
        let run = runner.run_point().await;
        let candidate = run
            .cases
            .iter()
            .find(|case| case.chain == vec!["grow:8:repeat".to_string()])
            .expect("the grow:8:repeat case");
        assert_eq!(candidate.candidate, Candidate::Unjudged);
        assert_eq!(verdict.evidence.payload, Some(candidate.sent_hex.clone()));
        assert_eq!(
            verdict.detail,
            "crash candidate on 127.0.0.1:9/udp field raw mutation grow:8:repeat: \
             not reproduced (reproduce_count is 0)"
        );
        assert!(run.stopped.is_none(), "{:?}", run.stopped);
        assert_eq!(
            shared
                .state
                .counters(job.job_id())
                .expect("counters")
                .crashes,
            0
        );
    }

    /// Review finding Q2: once the triage has judged a candidate the answer is
    /// the lane's, and a later stop cannot turn it back into an open question.
    /// A flaky candidate that three replays did not reproduce, followed by the
    /// job running out of budget, is a clean point — not "stopped before
    /// reproduction", which the triage disproves (spec call 14).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn judged_candidate_then_stop_is_clean() {
        let mock = MockBackend::new(MockReply::Echo);
        // `repeat: false`: the pattern kills the target once, so no replay
        // reproduces it.
        mock.dies_on_pattern(vec![0xde, 0xad, 0xbe, 0xef], 8, 2, false);
        let profile = with_hex_seed(l4_profile(vec![udp_target(9)], 10), "deadbeef0000");
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        // 1 baseline + 2 cases + 2 failed probes + 1 recovery poll +
        // 3 x (replay + 2 probes) = 15: the triage finishes, and the next
        // loop case is the charge the budget refuses.
        let job = job.with_budget(15);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");
        let registry = registry_with(&job, &runner);

        let run = runner.run_point().await;
        assert_eq!(run.stopped, Some(StopReason::Budget));
        assert!(run.crash.is_none(), "{:?}", run.crash);
        assert_eq!(
            run.cases[1].candidate,
            Candidate::NotReproduced {
                reproduced: 0,
                attempts: 3,
            }
        );

        let verdict = run_check(&CrashCheck::new(registry), &runner).await;

        assert_eq!(verdict.outcome, Outcome::Clean);
        assert_eq!(verdict.confidence, Confidence::Firm);
        assert!(
            !verdict.detail.contains("crash candidate"),
            "the triage judged it: {}",
            verdict.detail
        );
    }

    /// Review finding Q1: a wire write that fails is not a crafting mistake the
    /// run can shrug off — the stimulus was charged and never reached the wire.
    /// The job stops on it, and the point reports an error rather than a clean
    /// run of "0 cases sent".
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wire_write_failure_stops_the_job_and_is_not_clean() {
        let mock = MockBackend::new(MockReply::Echo);
        let profile = l4_profile(vec![udp_target(9)], 10);
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        // Discovery only opens a capture, so the wire breaks after it.
        mock.fail_injects_with_wire_write();
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");
        let registry = registry_with(&job, &runner);

        let run = runner.run_point().await;

        assert_eq!(
            run.stopped,
            Some(StopReason::WireWrite("mock wire down".to_string()))
        );
        // The baseline is the one stimulus that was attempted: charged before
        // the send, as every stimulus is, and not a case.
        assert_eq!(job.charged(), 1);
        assert!(run.cases.is_empty(), "{:?}", run.cases);
        assert_eq!(
            shared.state.counters(job.job_id()).expect("counters").cases,
            0
        );

        let verdict = run_check(&CrashCheck::new(registry), &runner).await;
        assert_eq!(verdict.outcome, Outcome::Error);
        assert_eq!(verdict.confidence, Confidence::Tentative);
        assert!(
            verdict.detail.contains("wire write failed: mock wire down"),
            "the verdict names the wire failure: {}",
            verdict.detail
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reaction_check_reports_icmp_as_info_class() {
        let mock = MockBackend::new(MockReply::Icmp {
            icmp_type: 3,
            code: 3,
        });
        let profile = l4_profile(vec![udp_target(9)], 10);
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");
        let registry = registry_with(&job, &runner);

        let verdict = run_check(&ReactionCheck::new(Arc::clone(&registry)), &runner).await;

        assert_eq!(verdict.outcome, Outcome::Vulnerable);
        assert_eq!(verdict.confidence, Confidence::Firm);
        let l4 = verdict.evidence.l4.as_ref().expect("the reaction evidence");
        assert_eq!(
            l4.oracle,
            L4Oracle::Icmp {
                icmp_type: 3,
                code: 3
            }
        );
        assert_eq!(l4.reproduced, (10, 10));
        assert!(l4.liveness_before);
        assert!(l4.liveness_after);
        assert_eq!(verdict.evidence.payload, Some(l4.sent_hex.clone()));
        assert!(
            verdict.detail.contains("icmp(3,3) x 10"),
            "detail counts the reaction: {}",
            verdict.detail
        );

        let crash = run_check(&CrashCheck::new(registry), &runner).await;
        assert_eq!(crash.outcome, Outcome::Clean);
        assert_eq!(mock.inject_count(), 11);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reaction_check_reports_reset() {
        let mock = MockBackend::new(MockReply::Rst);
        let profile = l4_profile(vec![tcp_target(80)], 7);
        let (shared, job, plans, disc) =
            setup(Arc::clone(&mock), profile, &fields(&["tcp.flags"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "tcp.flags");
        let registry = registry_with(&job, &runner);

        let verdict = run_check(&ReactionCheck::new(registry), &runner).await;

        assert_eq!(verdict.outcome, Outcome::Vulnerable);
        let l4 = verdict.evidence.l4.as_ref().expect("the reaction evidence");
        assert_eq!(l4.oracle, L4Oracle::Reset);
        assert!(
            verdict.detail.contains("reset x "),
            "detail counts the resets: {}",
            verdict.detail
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn clean_run_is_clean_for_both() {
        let mock = MockBackend::new(MockReply::Echo);
        let profile = l4_profile(vec![udp_target(9)], 10);
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");
        let registry = registry_with(&job, &runner);

        let crash = run_check(&CrashCheck::new(Arc::clone(&registry)), &runner).await;
        let reaction = run_check(&ReactionCheck::new(registry), &runner).await;

        assert_eq!(crash.outcome, Outcome::Clean);
        assert_eq!(crash.confidence, Confidence::Firm);
        assert_eq!(reaction.outcome, Outcome::Clean);
        assert!(crash.evidence.l4.is_none());
        assert!(
            crash.detail.contains("10 cases sent"),
            "detail counts the cases: {}",
            crash.detail
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dry_run_is_clean_with_render() {
        let mock = MockBackend::new(MockReply::Echo);
        let mut profile = l4_profile(vec![udp_target(9)], 100);
        profile.l4.dry_run = true;
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");
        let registry = registry_with(&job, &runner);

        let crash = run_check(&CrashCheck::new(Arc::clone(&registry)), &runner).await;
        let reaction = run_check(&ReactionCheck::new(registry), &runner).await;

        let run = runner.run_point().await;
        assert_eq!(crash.outcome, Outcome::Clean);
        assert_eq!(reaction.outcome, Outcome::Clean);
        for verdict in [&crash, &reaction] {
            assert!(
                verdict
                    .detail
                    .starts_with("dry run: 50 cases rendered for raw; first "),
                "detail renders the dry run: {}",
                verdict.detail
            );
            assert_eq!(
                verdict.evidence.payload,
                Some(run.cases[0].sent_hex.clone())
            );
        }
        assert_eq!(mock.inject_count(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn missing_runner_is_error_verdict() {
        let mock = MockBackend::new(MockReply::Echo);
        let profile = l4_profile(vec![udp_target(9)], 10);
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");
        let empty = Arc::new(RunnerRegistry::new());

        let verdict = run_check(&CrashCheck::new(empty), &runner).await;

        assert_eq!(verdict.outcome, Outcome::Error);
        assert_eq!(verdict.confidence, Confidence::Tentative);
        assert!(
            verdict.detail.contains("probe_host_for"),
            "detail names the missing step: {}",
            verdict.detail
        );
        assert!(verdict.evidence.l4.is_none());
        assert_eq!(mock.inject_count(), 0);
    }

    /// Tester (stage 5): once the stop ladder tripped on one point, a second
    /// point of the same job gets the `error`/`tentative` stopped verdict from
    /// **both** checks, naming the reason, and nothing more goes out.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stopped_job_is_an_error_verdict_for_an_untouched_point() {
        let mock = MockBackend::new(MockReply::Silence);
        let mut profile = l4_profile(vec![udp_target(9)], 50);
        profile.l4.consecutive_timeouts = 3;
        let (shared, job, plans, disc) = setup(
            Arc::clone(&mock),
            profile,
            &fields(&["raw", "udp.length"]),
            1000,
        );
        let first = runner_for(&shared, &job, &plans, &disc.points, "raw");
        let second = runner_for(&shared, &job, &plans, &disc.points, "udp.length");
        let registry = registry_with(&job, &first);
        registry.register(
            &job.marker(),
            second.point().id.as_str(),
            Arc::clone(&second),
        );

        let tripped = run_check(&CrashCheck::new(Arc::clone(&registry)), &first).await;
        // Three silent cases went out; the run has cases, so it is judged, not
        // reported as stopped: silence alone is never a crash.
        assert_eq!(tripped.outcome, Outcome::Clean);
        assert!(
            tripped
                .detail
                .contains("3 cases sent on 127.0.0.1:9/udp field raw; no crash"),
            "{}",
            tripped.detail
        );
        let injected = mock.inject_count();
        // Baseline (silent, so silence *is* the baseline), three silent cases,
        // and one passing liveness probe after each of the first two; the third
        // case trips the ladder, so no probe follows it.
        assert_eq!(injected, 1 + 3 + 2);

        let crash = run_check(&CrashCheck::new(Arc::clone(&registry)), &second).await;
        let reaction = run_check(&ReactionCheck::new(registry), &second).await;
        for verdict in [&crash, &reaction] {
            assert_eq!(verdict.outcome, Outcome::Error);
            assert_eq!(verdict.confidence, Confidence::Tentative);
            assert_eq!(
                verdict.detail,
                "the packet lane stopped before any case on 127.0.0.1:9/udp field udp.length: consecutive_timeouts: 3 silent cases in a row"
            );
            assert!(verdict.evidence.l4.is_none());
            assert!(verdict.evidence.payload.is_none());
        }
        assert_eq!(
            mock.inject_count(),
            injected,
            "a stopped job sends nothing more"
        );
    }

    /// Tester (stage 5): the three operator-facing detail lines, each as a
    /// literal over a hand-built run.
    #[test]
    fn detail_lines_are_literal() {
        use crate::oracle::CaseClass;
        use crate::state::{CaseOutcome, CaseRecord, CrashRecord, PointRun};
        use aitm_scan_model::L4Evidence;

        let case = |index: u32, class: CaseClass, hex: &str, outlier: bool| CaseRecord {
            index,
            seed_id: "127.0.0.1:9/udp#0".to_string(),
            chain: vec![format!("case{index}")],
            sent_hex: hex.to_string(),
            outcome: CaseOutcome::Sent {
                class,
                elapsed_ms: 1,
                latency_outlier: outlier,
            },
            candidate: Candidate::No,
        };
        let icmp = CaseClass::Icmp {
            icmp_type: 3,
            code: 3,
        };
        let long_hex = "ab".repeat(40);
        let run = PointRun {
            point_id: "l4:127.0.0.1:9/udp/raw".to_string(),
            target: "127.0.0.1:9/udp".to_string(),
            field: FieldPath::Raw,
            rng_seed: 1,
            dry_run: false,
            recovery_wait: Duration::from_secs(10),
            baseline: Some(CaseClass::Clean),
            cases: vec![
                case(0, icmp, &long_hex, false),
                case(1, CaseClass::Reset, "00", true),
                case(2, icmp, "01", false),
                case(3, CaseClass::Clean, "02", true),
            ],
            crash: None,
            stopped: None,
        };
        assert_eq!(
            super::reaction_detail(&run),
            "l4 reactions on 127.0.0.1:9/udp field raw: icmp(3,3) x 2; reset x 1; latency outliers 2"
        );
        assert_eq!(
            super::dry_run_detail(&run),
            format!(
                "dry run: 4 cases rendered for raw; first {}...",
                "ab".repeat(32)
            )
        );

        let evidence = L4Evidence {
            sent_hex: "deadbeef00000000".to_string(),
            seed_id: "127.0.0.1:9/udp#0".to_string(),
            rng_seed: 1,
            mutation_chain: vec!["grow:8".to_string(), "raw:bit_flip@3".to_string()],
            prior_messages: 0,
            oracle: L4Oracle::LivenessFailed,
            liveness_before: true,
            liveness_after: false,
            reproduced: (3, 3),
            scope_entry: "entry".to_string(),
        };
        let recovered = CrashRecord {
            case_index: 1,
            recovered: true,
            evidence: evidence.clone(),
        };
        assert_eq!(
            super::crash_detail(&run, &recovered),
            "l4 crash on 127.0.0.1:9/udp field raw mutation grow:8;raw:bit_flip@3; reproduced 3/3; liveness before true, after false"
        );
        let mut outage_evidence = evidence;
        outage_evidence.reproduced = (0, 0);
        let outage = CrashRecord {
            case_index: 1,
            recovered: false,
            evidence: outage_evidence,
        };
        assert_eq!(
            super::crash_detail(&run, &outage),
            "l4 crash on 127.0.0.1:9/udp field raw mutation grow:8;raw:bit_flip@3; reproduced 0/0; liveness before true, after false; target did not recover within 10s"
        );
        let mut fast = run.clone();
        fast.recovery_wait = Duration::from_millis(100);
        assert!(
            super::crash_detail(&fast, &outage).ends_with("; target did not recover within 100ms")
        );
        let verdict = super::crash_verdict(&fast, &outage);
        assert_eq!(
            verdict.evidence.matched.as_deref(),
            Some("liveness failed after case; target did not recover within 100ms")
        );
        assert_eq!(
            verdict.evidence.payload.as_deref(),
            Some("deadbeef00000000")
        );
        let verdict = super::crash_verdict(&run, &recovered);
        assert_eq!(
            verdict.evidence.matched.as_deref(),
            Some("liveness failed after case; reproduced 3/3")
        );

        // A short first case is printed whole, with no ellipsis.
        let mut short = run;
        short.cases.truncate(1);
        short.cases[0].sent_hex = "0102".to_string();
        assert_eq!(
            super::dry_run_detail(&short),
            "dry run: 1 cases rendered for raw; first 0102"
        );
        short.cases.clear();
        assert_eq!(
            super::dry_run_detail(&short),
            "dry run: 0 cases rendered for raw; first "
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn order_is_irrelevant() {
        let mock = MockBackend::new(MockReply::Echo);
        mock.dies_on_pattern(vec![0xde, 0xad, 0xbe, 0xef], 8, 2, true);
        let profile = with_hex_seed(l4_profile(vec![udp_target(9)], 50), "deadbeef0000");
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");
        let registry = registry_with(&job, &runner);

        let reaction = run_check(&ReactionCheck::new(Arc::clone(&registry)), &runner).await;
        let crash = run_check(&CrashCheck::new(registry), &runner).await;

        assert_eq!(reaction.outcome, Outcome::Clean);
        assert_eq!(crash.outcome, Outcome::Vulnerable);
        assert_eq!(
            crash
                .evidence
                .l4
                .as_ref()
                .expect("the crash evidence")
                .reproduced,
            (3, 3)
        );
        assert_eq!(mock.inject_count(), 17);
    }

    /// Tester (fix round): a triage the case cap cut short (finding F2) is an
    /// interrupted triage like any other (finding F1), and the verdict names
    /// the cap — literally — as the reason nothing was reproduced.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cap_interrupted_triage_names_the_cap_in_its_detail() {
        let mock = MockBackend::new(MockReply::Echo);
        mock.dies_on_pattern(vec![0xde, 0xad, 0xbe, 0xef], 8, 2, true);
        // Two cases is the whole job: the crashing case is the last one the
        // cap allows, so not one replay fits.
        let profile = with_hex_seed(l4_profile(vec![udp_target(9)], 2), "deadbeef0000");
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");
        let registry = registry_with(&job, &runner);

        let verdict = run_check(&CrashCheck::new(registry), &runner).await;

        assert_eq!(verdict.outcome, Outcome::Inconclusive);
        assert_eq!(verdict.confidence, Confidence::Tentative);
        assert_eq!(
            verdict.detail,
            "crash candidate on 127.0.0.1:9/udp field raw mutation grow:8: \
             case cap reached: 2 cases sent before reproduction"
        );
        let trigger = mock.injected().get(2).cloned().expect("the third inject");
        assert_eq!(verdict.evidence.payload, Some(hex_encode(&trigger)));
        assert!(verdict.evidence.l4.is_none(), "{:?}", verdict.evidence.l4);
        assert_eq!(verdict.poc_hint, None);
        assert_eq!(mock.inject_count(), 5, "no replay went out");
        let counters = shared.state.counters(job.job_id()).expect("counters");
        assert_eq!(counters.cases, 2);
        assert_eq!(counters.crashes, 0);
        assert_eq!(counters.retired_elements, 0);
    }

    /// Break the mock's wire once `injects` frames have gone out: the next
    /// inject fails with `WireWrite`. Keyed off the inject count, so the test
    /// does not race a sleep; the mock's `reply_delay` keeps consecutive
    /// injects far enough apart for the 1 ms poll to land between them.
    fn break_wire_after(mock: &Arc<MockBackend>, injects: usize) -> tokio::task::JoinHandle<()> {
        let mock = Arc::clone(mock);
        tokio::spawn(async move {
            for _ in 0..20_000 {
                if mock.inject_count() >= injects {
                    mock.fail_injects_with_wire_write();
                    return;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            panic!("the wire never saw {injects} injects");
        })
    }

    /// Tester (fix rounds, review finding Q1): the wire breaks on the fourth
    /// case, not the baseline. The three cases that went out are kept, the
    /// failed one is charged (the charge precedes the send) but is not a case,
    /// and the job stops on `WireWrite` — so this point is judged on what was
    /// sent, and an untouched point of the same job reports the wire failure
    /// as its stop, by its literal.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wire_write_on_the_nth_case_stops_the_job_and_keeps_the_sent_cases() {
        let mock = MockBackend::new(MockReply::Echo);
        mock.reply_delay(Duration::from_millis(30));
        let profile = l4_profile(vec![udp_target(9)], 10);
        let (shared, job, plans, disc) = setup(
            Arc::clone(&mock),
            profile,
            &fields(&["raw", "ipv4.ttl"]),
            1000,
        );
        let first = runner_for(&shared, &job, &plans, &disc.points, "raw");
        let second = runner_for(&shared, &job, &plans, &disc.points, "ipv4.ttl");
        let registry = registry_with(&job, &first);
        registry.register(
            &job.marker(),
            second.point().id.as_str(),
            Arc::clone(&second),
        );
        // 1 baseline + 3 cases go out; the fourth case meets the broken wire.
        let breaker = break_wire_after(&mock, 4);

        let run = first.run_point().await;
        breaker.await.expect("the wire broke");

        assert_eq!(run.cases.len(), 3, "{:?}", run.cases);
        assert!(run
            .cases
            .iter()
            .all(|case| case.class() == Some(CaseClass::Clean)));
        assert_eq!(
            run.stopped,
            Some(StopReason::WireWrite("mock wire down".to_string()))
        );
        assert!(run.crash.is_none());
        assert_eq!(
            mock.inject_count(),
            4,
            "the fourth case never reached the wire"
        );
        assert_eq!(
            job.charged(),
            5,
            "the failed case was charged before the send"
        );
        let stats = shared.state.stats(job.job_id()).expect("stats");
        assert_eq!(stats.l4.cases, 3, "the failed case is not a case");
        assert_eq!(stats.cases_unsendable, 0, "nor an unsendable one");
        assert_eq!(
            stats.stopped,
            Some(StopReason::WireWrite("mock wire down".to_string()))
        );

        // The point with cases is judged on them: no crash, no reaction.
        let crash = run_check(&CrashCheck::new(Arc::clone(&registry)), &first).await;
        assert_eq!(crash.outcome, Outcome::Clean);
        assert_eq!(
            crash.detail,
            "3 cases sent on 127.0.0.1:9/udp field raw; no crash"
        );
        let reaction = run_check(&ReactionCheck::new(Arc::clone(&registry)), &first).await;
        assert_eq!(reaction.outcome, Outcome::Clean);
        assert_eq!(
            reaction.detail,
            "3 cases sent on 127.0.0.1:9/udp field raw; no protocol reaction"
        );

        // The untouched point sends nothing and names the wire failure.
        let starved = run_check(&CrashCheck::new(registry), &second).await;
        assert_eq!(starved.outcome, Outcome::Error);
        assert_eq!(starved.confidence, Confidence::Tentative);
        assert_eq!(
            starved.detail,
            "the packet lane stopped before any case on 127.0.0.1:9/udp field ipv4.ttl: \
             wire write failed: mock wire down"
        );
        assert_eq!(mock.inject_count(), 4, "a stopped job sends nothing more");
        assert_eq!(job.charged(), 5);
    }

    /// Tester (fix rounds, review findings Q1/Q2): the wire breaks on the first
    /// reproduction replay, after the target came back. A replay that never
    /// left the host is not an attempt, so the candidate is `Interrupted` by
    /// the `WireWrite` stop — not confirmed, not judged — and the crash check
    /// surfaces it as inconclusive, naming the wire failure as the reason
    /// nothing was reproduced.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wire_write_inside_a_triage_replay_is_an_interrupted_candidate() {
        let mock = MockBackend::new(MockReply::Echo);
        mock.reply_delay(Duration::from_millis(30));
        mock.dies_on_pattern(vec![0xde, 0xad, 0xbe, 0xef], 8, 2, true);
        let profile = with_hex_seed(l4_profile(vec![udp_target(9)], 50), "deadbeef0000");
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");
        let registry = registry_with(&job, &runner);
        // 1 baseline + 2 cases + 2 failed probes + 1 passing recovery poll = 6;
        // the replay is the seventh inject, and it meets the broken wire.
        let breaker = break_wire_after(&mock, 6);

        let run = runner.run_point().await;
        breaker.await.expect("the wire broke");

        assert_eq!(mock.inject_count(), 6, "the replay never reached the wire");
        assert_eq!(job.charged(), 7, "the replay was charged before the send");
        assert_eq!(run.cases.len(), 2, "{:?}", run.cases);
        assert_eq!(
            run.cases[1].candidate,
            Candidate::Interrupted {
                stop: StopReason::WireWrite("mock wire down".to_string()),
            }
        );
        assert_eq!(
            run.stopped,
            Some(StopReason::WireWrite("mock wire down".to_string()))
        );
        assert!(run.crash.is_none(), "{:?}", run.crash);
        assert_eq!(
            shared.state.counters(job.job_id()),
            Some(aitm_scan_model::L4Counters {
                cases: 2,
                crashes: 0,
                // The candidate's two failed probes; the recovery poll passed.
                liveness_failures: 2,
                retired_elements: 0,
            })
        );
        assert!(!shared.state.is_retired(job.job_id(), &run.point_id));

        let verdict = run_check(&CrashCheck::new(registry), &runner).await;
        assert_eq!(verdict.outcome, Outcome::Inconclusive);
        assert_eq!(verdict.confidence, Confidence::Tentative);
        assert_eq!(
            verdict.detail,
            "crash candidate on 127.0.0.1:9/udp field raw mutation grow:8: \
             wire write failed: mock wire down before reproduction"
        );
        let trigger = mock.injected().get(2).cloned().expect("the third inject");
        assert_eq!(verdict.evidence.payload, Some(hex_encode(&trigger)));
        assert!(verdict.evidence.l4.is_none(), "{:?}", verdict.evidence.l4);
        assert_eq!(mock.inject_count(), 6, "the check sent nothing");
    }
}
