//! The native `sqli-time` and `cmdi-time` checks (spec D8.2). Implemented by T3 task 8.
//!
//! Both answer one question: **does the target's response time follow a delay
//! we asked it to take?** If a parameter reaches a SQL engine or a shell, the
//! injected delay is honoured and the response time moves with it; if it does
//! not, the response time stays where it was. That differential is the whole
//! finding. Nothing is read, written, executed or exfiltrated — the payload
//! asks for a pause of a few seconds and for nothing else, which is why these
//! are detection-grade probes under the spec's anti-goals.
//!
//! Three properties make the verdict trustworthy rather than a guess at noise:
//!
//! 1. **The delays alternate.** The schedule is long/short/long/short, so a
//!    target that simply got slower — a cold cache, a busy neighbour — does not
//!    look like a target that obeyed us. Only a response time that goes *up and
//!    down with the number we asked for* fits the line (ZAP's blind-timing rule,
//!    `docs/research/17-burp-style-scanner-architecture.md` §3.6).
//! 2. **The acceptance rule is published, not invented.** [`crate::timing`]
//!    applies ZAP's correlation (0.15) and slope (0.30) error ranges, and the
//!    same code answers the Rhai `probe.timing_fit`, so the native and scripted
//!    halves of the catalogue cannot disagree about one target.
//! 3. **A partial series is never a verdict.** Two measurements fit any straight
//!    line exactly, so a family whose schedule did not complete is dropped rather
//!    than regressed. A run that was cut short says `inconclusive`, and so does
//!    a run that sent every probe it planned but lost a family to a refused
//!    one: `clean` means every family completed and none correlated.
//!
//! **This check never waits.** It asks the target for the delay and then reads
//! the `elapsed_ms` the lane measured (spec D4, "Timing without `sleep`"), so a
//! check that probes for a three-second pause still returns in microseconds in a
//! test and costs the job nothing but the target's own latency in a real run.
//! The integration test `no_sleep_call_in_the_source` pins that literally: this
//! file calls no sleep, in any form. It does *spell* one — `pg_sleep(n)` is the
//! payload that asks PostgreSQL to wait — and that is the point: what the
//! module asks a target for is written out where an operator can read it.
//!
//! **Cost.** Four probes per family, `MAX_TIMING_PROBES_PER_POINT` per point,
//! hence at most two families tried per point (AC T3-4's "<= 8 probes per
//! point"). There is no repeat loop on top of that: the alternating schedule
//! already asks for each delay twice, and the cap leaves no room for more.

use std::sync::Arc;

use aitm_poc::Severity;
use aitm_scan_model::{
    Check, CheckCost, CheckMeta, CheckOrigin, Confidence, Evidence, FlowRef, InsertionKind,
    InsertionPoint, Intensity, LaneKind, Outcome, Payload, PayloadMode, ProbeHost, Speed,
    Technique, Timing, Verdict,
};
use futures::future::BoxFuture;

use crate::gate::{may_send, no_finding, ProbeTally, STOPPED};
use crate::timing::{correlated, fit};

/// The hard per-point probe ceiling for a timing check (AC T3-4).
const MAX_TIMING_PROBES_PER_POINT: u32 = 8;

/// Probes in one family's schedule: two long delays and two short ones.
const PROBES_PER_FAMILY: usize = 4;

/// How many families the ceiling leaves room for: two.
const MAX_FAMILIES_PER_POINT: usize = MAX_TIMING_PROBES_PER_POINT as usize / PROBES_PER_FAMILY;

/// The alternating schedule at `speed: fast` and `speed: normal`, in seconds.
///
/// One second is long enough to stand clear of ordinary jitter on a loopback or
/// LAN target and short enough that four probes cost eight seconds of wall time.
const DELAYS_S: [f32; PROBES_PER_FAMILY] = [1.0, 3.0, 1.0, 3.0];

/// The alternating schedule at `speed: thorough`, in seconds.
///
/// Wider delays separate a real injection from a noisy link, at the cost of
/// fourteen seconds per family.
const THOROUGH_DELAYS_S: [f32; PROBES_PER_FAMILY] = [2.0, 5.0, 2.0, 5.0];

/// One payload shape, named for the engine it targets.
///
/// `template` renders the family's payload for a requested delay in seconds.
/// Families are tried in order and the first one whose series correlates ends
/// the run, so the most widely applicable shape goes first.
struct Family {
    /// The engine this shape targets; it names the family in the verdict detail.
    name: &'static str,
    /// Renders the payload that asks for `n` seconds.
    template: fn(f32) -> String,
}

/// MySQL and MariaDB, string context: close the quote, add the delay, comment out
/// the tail. The trailing space after `--` is required by MySQL's comment syntax.
fn mysql(n: f32) -> String {
    format!("' AND SLEEP({n})-- ")
}

/// PostgreSQL: concatenate the delay call onto the quoted value.
fn postgres(n: f32) -> String {
    format!("'||pg_sleep({n})--")
}

/// Microsoft SQL Server, whose delay is a statement rather than a function.
fn mssql(n: f32) -> String {
    format!("'; WAITFOR DELAY '0:0:{n}'--")
}

/// POSIX shells: terminate the command and run the delay as the next one.
fn sh(n: f32) -> String {
    format!("; sleep {n}")
}

/// POSIX shells again, where the value lands inside an existing command line and
/// a command substitution is the only way in.
fn sh_subshell(n: f32) -> String {
    format!("$(sleep {n})")
}

/// Windows `cmd.exe`, whose closest equivalent is `timeout`.
fn windows(n: f32) -> String {
    format!("& timeout /T {n}")
}

/// The catalogue entry for time-based blind SQL injection (session call S3).
#[must_use]
pub fn sqli_time() -> Arc<dyn Check> {
    Arc::new(TimingCheck {
        meta: CheckMeta {
            id: "sqli-time".to_string(),
            name: "Time-based blind SQL injection".to_string(),
            class: "sqli".to_string(),
            lanes: vec![LaneKind::Http],
            kinds: injectable_kinds(),
            intensity: Intensity::Medium,
            cost: CheckCost::Medium,
            technique: Technique::Timing,
            severity: Severity::Critical,
            confidence_max: Confidence::Firm,
            needs_baseline: true,
            wants_traits: None,
            targets_session: false,
            scope: aitm_scan_model::CheckScope::Point,
            cwe: Some(89),
            description: "Asks the database for a bounded pause through the point, in an \
                          alternating long/short schedule, and reports when the observed \
                          response time tracks the delay that was requested."
                .to_string(),
            remediation: Some(
                "Pass the value as a bound parameter to a prepared statement so the \
                 database never parses it as SQL; allow-list the value where the query \
                 shape itself is dynamic (sort columns, table names)."
                    .to_string(),
            ),
            origin: CheckOrigin::Native,
        },
        families: sqli_families(),
    })
}

/// The SQL delay shapes, in the order they are tried. MySQL first: it is the
/// most widely deployed of the three, and its payload is the one that works in
/// the commonest context (a quoted string).
fn sqli_families() -> Vec<Family> {
    vec![
        Family {
            name: "mysql",
            template: mysql,
        },
        Family {
            name: "postgres",
            template: postgres,
        },
        Family {
            name: "mssql",
            template: mssql,
        },
    ]
}

/// The catalogue entry for time-based blind OS command injection (call S3).
#[must_use]
pub fn cmdi_time() -> Arc<dyn Check> {
    Arc::new(TimingCheck {
        meta: CheckMeta {
            id: "cmdi-time".to_string(),
            name: "Time-based blind OS command injection".to_string(),
            class: "cmdi".to_string(),
            lanes: vec![LaneKind::Http],
            kinds: injectable_kinds(),
            intensity: Intensity::Medium,
            cost: CheckCost::Medium,
            technique: Technique::Timing,
            severity: Severity::Critical,
            confidence_max: Confidence::Firm,
            needs_baseline: true,
            wants_traits: None,
            targets_session: false,
            scope: aitm_scan_model::CheckScope::Point,
            cwe: Some(78),
            description: "Asks the operating system for a bounded pause through the point, \
                          in an alternating long/short schedule, and reports when the \
                          observed response time tracks the delay that was requested."
                .to_string(),
            remediation: Some(
                "Never build a shell command line from request data: call the program \
                 directly with an argument vector, and allow-list the values that select \
                 what runs."
                    .to_string(),
            ),
            origin: CheckOrigin::Native,
        },
        families: cmdi_families(),
    })
}

/// The command-injection delay shapes, in the order they are tried. The two
/// POSIX shapes come first: a Windows target that honours `&` usually honours
/// `;` too, and the reverse is not true.
fn cmdi_families() -> Vec<Family> {
    vec![
        Family {
            name: "sh",
            template: sh,
        },
        Family {
            name: "sh_subshell",
            template: sh_subshell,
        },
        Family {
            name: "windows",
            template: windows,
        },
    ]
}

/// The insertion kinds a value-injection check applies to: everywhere a request
/// carries an attacker-controlled *value*. Shared with `sqli-boolean`.
fn injectable_kinds() -> Vec<InsertionKind> {
    vec![
        InsertionKind::Query,
        InsertionKind::BodyParam,
        InsertionKind::JsonValue,
        InsertionKind::XmlValue,
        InsertionKind::MultipartValue,
        InsertionKind::Header,
        InsertionKind::Cookie,
        InsertionKind::PathSegment,
    ]
}

/// A blind time-based check: one metadata block and an ordered list of payload
/// families, all driven by the same oracle.
struct TimingCheck {
    meta: CheckMeta,
    families: Vec<Family>,
}

/// The schedule for a speed setting.
///
/// `fast` keeps the normal schedule rather than a shorter one: a one-second
/// delay is already the smallest that survives jitter, and cutting the series
/// instead would leave too few points to regress.
fn schedule(speed: Speed) -> [f32; PROBES_PER_FAMILY] {
    match speed {
        Speed::Fast | Speed::Normal => DELAYS_S,
        Speed::Thorough => THOROUGH_DELAYS_S,
    }
}

/// The longest delay in a schedule: the payload an operator re-sends by hand to
/// watch the pause for themselves.
fn longest(delays: &[f32]) -> f32 {
    delays.iter().copied().fold(0.0_f32, f32::max)
}

/// The verdict for a family whose observed delays tracked the requested ones.
fn tracked(
    family: &Family,
    payload: String,
    timing: Timing,
    probe_flows: Vec<FlowRef>,
    baseline_flow: Option<FlowRef>,
) -> Verdict {
    let detail = format!(
        "{name}: observed delay tracks the requested delay (r={r:.2}, slope={slope:.0} ms/s)",
        name = family.name,
        r = timing.r,
        slope = timing.slope,
    );
    Verdict {
        outcome: Outcome::Vulnerable,
        // Never `certain`: a delay is circumstantial by construction, however
        // well it fits. Only a technique that sees its own payload come back can
        // be certain (`confidence_max` says the same).
        confidence: Confidence::Firm,
        evidence: Evidence {
            payload: Some(payload),
            // The fitter makes no claim; this check did (`correlated(&timing)`
            // held), so the evidence says so for the reader (spec D8.2,
            // coordinator decision 2).
            timing: Some(Timing {
                correlated: true,
                ..timing
            }),
            probe_flows,
            baseline_flow,
            ..Evidence::default()
        },
        detail,
        // A blind differential has no stable response assertion to reproduce, so
        // no PoC hint and no `FindingRecord` (spec D6).
        poc_hint: None,
        location: None,
        more: Vec::new(),
    }
}

impl Check for TimingCheck {
    fn meta(&self) -> &CheckMeta {
        &self.meta
    }

    fn run<'a>(
        &'a self,
        _point: &'a InsertionPoint,
        host: &'a dyn ProbeHost,
    ) -> BoxFuture<'a, Verdict> {
        Box::pin(async move {
            let delays = schedule(host.profile().speed);
            let families = &self.families[..self.families.len().min(MAX_FAMILIES_PER_POINT)];
            let planned = families.len() * delays.len();

            // Nothing at all, not even a baseline, once the job has stopped:
            // the gate goes above every request a check makes, as it does in
            // `sqli_boolean.rs` and `h2_observe.rs` (tester finding B1).
            if !may_send(host, 1) {
                return no_finding(
                    Outcome::Inconclusive,
                    format!("{STOPPED} before the baseline"),
                );
            }

            // The baseline re-centres the series. It moves neither the slope nor
            // the correlation (`timing::fit` documents that invariant), so a
            // point whose baseline the lane could not fetch is still decidable:
            // the evidence then simply carries no baseline.
            let (baseline_ms, baseline_flow) = match host.baseline().await {
                Ok(resp) => (vec![resp.elapsed_ms], resp.flow),
                Err(_) => (Vec::new(), None),
            };

            let mut tally = ProbeTally::new("delay probes", planned);
            // Families whose schedule was broken by a *refused* probe rather
            // than by the job stopping. They cost their probes and taught
            // nothing, so they may not be counted as a quiet target.
            let mut abandoned = 0usize;

            for family in families {
                let mut requested: Vec<f32> = Vec::with_capacity(delays.len());
                let mut observed: Vec<u32> = Vec::with_capacity(delays.len());
                let mut probe_flows: Vec<FlowRef> = Vec::new();
                let mut refused_here = 0usize;

                for delay in delays {
                    if !may_send(host, 1) {
                        break;
                    }
                    let payload = Payload {
                        // The payloads close the value they are appended to, so
                        // they go after it; the point owns the encoding.
                        value: (family.template)(delay),
                        mode: PayloadMode::Suffix,
                        bytes: None,
                    };
                    tally.attempted();
                    let Ok(resp) = host.probe(&payload).await else {
                        // One refused probe is not a verdict, but it does cost
                        // this family its complete series.
                        tally.refused();
                        refused_here += 1;
                        continue;
                    };
                    requested.push(delay);
                    observed.push(resp.elapsed_ms);
                    probe_flows.extend(resp.flow);
                }

                // Only a complete schedule is evidence: a truncated series has
                // too few points for `r` to mean anything (two points fit any
                // line exactly), so an interrupted family is dropped, not fitted.
                if requested.len() < delays.len() {
                    if refused_here > 0 {
                        abandoned += 1;
                    }
                    continue;
                }
                let timing = fit(&requested, &observed, &baseline_ms);
                if correlated(&timing) {
                    let payload = (family.template)(longest(&delays));
                    return tracked(family, payload, timing, probe_flows, baseline_flow);
                }
            }

            if let Some(unfinished) = tally.unfinished() {
                return unfinished;
            }
            // Every probe the plan asked for was sent, but a family that lost
            // one of them was never fitted. `Clean` would claim the response
            // time did not track the delay for probes that were never
            // compared, so an abandoned family makes the run inconclusive and
            // the detail says how many.
            if abandoned > 0 {
                let was = if abandoned == 1 { "was" } else { "were" };
                return no_finding(
                    Outcome::Inconclusive,
                    format!(
                        "{abandoned} of {total} payload families {was} abandoned: a probe was \
                         refused part-way through its schedule, so the series could not be \
                         fitted",
                        total = families.len()
                    ),
                );
            }
            tally.conclude(format!(
                "the response time did not track the requested delay over {planned} \
                 probes in {families} payload families",
                families = families.len()
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        cmdi_families, longest, schedule, sqli_families, DELAYS_S, MAX_FAMILIES_PER_POINT,
        MAX_TIMING_PROBES_PER_POINT, PROBES_PER_FAMILY, THOROUGH_DELAYS_S,
    };
    use aitm_scan_model::Speed;

    /// The alternating long/short shape is the rule, not decoration: each
    /// schedule asks for exactly two distinct delays, twice each, in alternation.
    /// A monotonic schedule would score a target that merely slowed down.
    #[test]
    fn both_schedules_alternate_long_and_short() {
        for s in [DELAYS_S, THOROUGH_DELAYS_S] {
            assert_eq!(s.len(), 4);
            assert_eq!(s[0], s[2]);
            assert_eq!(s[1], s[3]);
            assert!(s[1] > s[0], "{s:?} is not long/short alternating");
        }
        assert_eq!(DELAYS_S, [1.0, 3.0, 1.0, 3.0]);
        assert_eq!(THOROUGH_DELAYS_S, [2.0, 5.0, 2.0, 5.0]);
    }

    /// `fast` and `normal` share the shorter schedule; only `thorough` widens it.
    #[test]
    fn thorough_is_the_only_speed_that_widens_the_schedule() {
        assert_eq!(schedule(Speed::Fast), DELAYS_S);
        assert_eq!(schedule(Speed::Normal), DELAYS_S);
        assert_eq!(schedule(Speed::Thorough), THOROUGH_DELAYS_S);
    }

    /// AC T3-4's arithmetic: eight probes per point, four per family, so two
    /// families. A fourth family added later would silently never run, and this
    /// is the test that says so.
    #[test]
    fn the_probe_ceiling_leaves_room_for_exactly_two_families() {
        assert_eq!(MAX_TIMING_PROBES_PER_POINT, 8);
        assert_eq!(PROBES_PER_FAMILY, 4);
        assert_eq!(MAX_FAMILIES_PER_POINT, 2);
        assert!(MAX_FAMILIES_PER_POINT * PROBES_PER_FAMILY <= MAX_TIMING_PROBES_PER_POINT as usize);
    }

    /// The evidence payload is the family's longest delay, the one whose pause an
    /// operator can see by hand.
    #[test]
    fn the_longest_delay_is_the_one_quoted_as_evidence() {
        assert_eq!(longest(&DELAYS_S), 3.0);
        assert_eq!(longest(&THOROUGH_DELAYS_S), 5.0);
        assert_eq!(longest(&[]), 0.0);
    }

    /// Both checks offer three families but may only spend two; the order is the
    /// one the verdict's detail will name, and the first two are what a point
    /// actually costs.
    #[test]
    fn the_families_are_ordered_and_named() {
        let sqli: Vec<&str> = sqli_families().iter().map(|f| f.name).collect();
        assert_eq!(sqli, vec!["mysql", "postgres", "mssql"]);
        let cmdi: Vec<&str> = cmdi_families().iter().map(|f| f.name).collect();
        assert_eq!(cmdi, vec!["sh", "sh_subshell", "windows"]);
        for names in [sqli, cmdi] {
            assert!(names.len() > MAX_FAMILIES_PER_POINT);
        }
    }

    /// The rendered payloads, one per family, at the schedule's long delay. A
    /// delay is written as a bare integer: `3`, not `3.0`, which is what a SQL
    /// engine and a shell both expect.
    #[test]
    fn every_family_renders_its_delay_as_a_bare_integer() {
        for family in sqli_families().iter().chain(cmdi_families().iter()) {
            let rendered = (family.template)(3.0);
            assert!(
                rendered.contains('3') && !rendered.contains("3.0"),
                "{}: {rendered}",
                family.name
            );
        }
        assert_eq!((sqli_families()[0].template)(3.0), "' AND SLEEP(3)-- ");
        assert_eq!(
            (sqli_families()[2].template)(3.0),
            "'; WAITFOR DELAY '0:0:3'--"
        );
        assert_eq!((cmdi_families()[0].template)(1.0), "; sleep 1");
        assert_eq!((cmdi_families()[2].template)(1.0), "& timeout /T 1");
    }
}
