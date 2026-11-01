//! The stop gate and the verdict epilogue every native check shares.
//!
//! Five checks had five copies of the same three things — the
//! cancel/budget/deadline gate, the "no evidence, no hint" verdict, and the
//! three-way ending (stopped / every probe refused / clean) — and copies drift
//! (review findings C1, Q-M1, Q-M2). They live here once.
//!
//! [`matching`](crate::matching) answers "what does the response say";
//! this module answers "may I send, and how did the run end". Neither reads
//! the other's half.

use std::time::Instant;

use aitm_scan_model::{Confidence, Evidence, InsertionPoint, Outcome, ProbeHost, Verdict};

/// The standing reason a run stopped early, in the words every check uses.
///
/// Spelled once. A check that needs a variant composes it from this
/// (`format!("{STOPPED} before the baseline")`, `format!("stopped: {STOPPED}")`),
/// so the sentence cannot drift between modules (Q2-2).
pub(crate) const STOPPED: &str = "the job was cancelled, out of budget or past its deadline";

/// The list form of [`STOPPED`], for a check that appends a fourth reason of
/// its own: `format!("{STOPPED_LIST}, or {extra}")`. Spelled out rather than
/// edited out of [`STOPPED`] at run time, so each reads as written (FQ-2).
pub(crate) const STOPPED_LIST: &str = "the job was cancelled, out of budget, past its deadline";

/// The point's name as a `detail` may quote it: scrubbed with the core
/// vocabulary and cut to [`Evidence::excerpt`]'s bound, exactly like a
/// `matched` excerpt.
///
/// A name is observed on the wire — a parameter can be called after the
/// credential it carries, or be as long as the target likes — and a `detail`
/// is read by every surface an `Evidence` is, so it gets the same two
/// treatments (spec D8.1, "Redaction"; final security review FS-1). One
/// helper, used by every check that names its point.
pub(crate) fn point_label(point: &InsertionPoint) -> String {
    Evidence::excerpt(&crate::matching::scrub(&point.name))
}

/// Whether the check may spend `need` more stimuli right now.
///
/// Three reasons to stop and the check owns all three: the job was cancelled,
/// it has less budget left than this costs, or it is past its deadline. The
/// host enforces them too, but a check that keeps asking after a cancellation
/// has still wasted the job's time, and `Check::run`'s contract is to stop
/// (spec D2). `need` is more than one wherever half a stimulus proves nothing
/// — a boolean pair is two — so the pair is never half-sent.
pub(crate) fn may_send(host: &dyn ProbeHost, need: u32) -> bool {
    !host.cancelled() && host.budget_left() >= need && Instant::now() < host.deadline()
}

/// A verdict that concluded nothing: no evidence, no PoC hint, and always
/// `tentative`, because a verdict that concluded nothing has nothing to be
/// confident about.
pub(crate) fn no_finding(outcome: Outcome, detail: impl Into<String>) -> Verdict {
    Verdict {
        outcome,
        confidence: Confidence::Tentative,
        evidence: Evidence::default(),
        detail: detail.into(),
        poc_hint: None,
        location: None,
        more: Vec::new(),
    }
}

/// What a run of `planned` stimuli actually managed, and how it ends.
///
/// `unit` names the stimulus in the operator-facing detail ("reflection
/// probes", "condition pairs"), so one epilogue speaks every check's own
/// vocabulary.
pub(crate) struct ProbeTally {
    unit: &'static str,
    planned: usize,
    sent: usize,
    failed: usize,
    /// A check-specific extra reason a run can stop early (the per-point probe
    /// cap), appended to the standard three.
    extra_stop: Option<String>,
}

impl ProbeTally {
    /// A tally of a run that plans `planned` stimuli of `unit`.
    pub(crate) fn new(unit: &'static str, planned: usize) -> Self {
        Self {
            unit,
            planned,
            sent: 0,
            failed: 0,
            extra_stop: None,
        }
    }

    /// Name a fourth reason this check can stop short of its plan.
    pub(crate) fn also_stopped_by(mut self, reason: String) -> Self {
        self.extra_stop = Some(reason);
        self
    }

    /// One more stimulus was attempted.
    pub(crate) fn attempted(&mut self) {
        self.sent += 1;
    }

    /// The stimulus just attempted was refused.
    pub(crate) fn refused(&mut self) {
        self.failed += 1;
    }

    /// `n` planned stimuli the check decided not to send — a family abandoned
    /// after a 5xx, say. They leave the plan, so a run that skipped them on
    /// purpose is not read as a run the job cut short.
    pub(crate) fn skipped(&mut self, n: usize) {
        self.planned = self.planned.saturating_sub(n);
    }

    /// The verdict for a run that did not reach its own plan, in this order:
    ///
    /// 1. **stopped early** — fewer stimuli were attempted than planned, so
    ///    the job was cancelled, out of budget, past its deadline or capped.
    ///    That is the scanner's own doing and is `Inconclusive`;
    /// 2. **every attempt refused** — the plan ran out and not one stimulus
    ///    came back. That is the target's doing and is `Error`.
    ///
    /// The order matters: `Error` feeds the per-host error ladder (spec D5),
    /// so a single refused probe followed by a cancellation must not be read
    /// as a failing target (review finding Q-M2).
    pub(crate) fn unfinished(&self) -> Option<Verdict> {
        if self.sent < self.planned {
            let reason = match &self.extra_stop {
                // The list form of the same sentence, with the extra reason
                // as its last item: "cancelled, out of budget, past its
                // deadline, or <extra>".
                Some(extra) => format!("{STOPPED_LIST}, or {extra}"),
                None => STOPPED.to_string(),
            };
            return Some(no_finding(
                Outcome::Inconclusive,
                format!(
                    "stopped after {sent} of {planned} {unit}: {reason}",
                    sent = self.sent,
                    planned = self.planned,
                    unit = self.unit,
                ),
            ));
        }
        if self.sent > 0 && self.failed == self.sent {
            return Some(no_finding(
                Outcome::Error,
                format!(
                    "every one of the {sent} {unit} was refused",
                    sent = self.sent,
                    unit = self.unit
                ),
            ));
        }
        None
    }

    /// [`Self::unfinished`], or a `Clean` verdict carrying `clean_detail`.
    pub(crate) fn conclude(self, clean_detail: String) -> Verdict {
        self.unfinished()
            .unwrap_or_else(|| no_finding(Outcome::Clean, clean_detail))
    }
}

#[cfg(test)]
mod tests {
    use aitm_scan_model::{Confidence, Evidence, Outcome};

    use aitm_scan_model::{InsertionKind, InsertionPoint, LaneKind, MAX_EXCERPT_BYTES};

    use super::{no_finding, point_label, ProbeTally, STOPPED, STOPPED_LIST};

    fn named(name: &str) -> InsertionPoint {
        InsertionPoint {
            id: "p".to_string(),
            lane: LaneKind::Http,
            kind: InsertionKind::Query,
            name: name.to_string(),
            path: None,
            example: None,
            flow: None,
            site_node: None,
            traits: Vec::new(),
            frequency: 1,
            method: None,
            url: None,
        }
    }

    /// A point's name is observed on the wire, so a `detail` that quotes it is
    /// bounded and scrubbed exactly like a `matched` excerpt: a credential-
    /// shaped name is redacted, an overlong one is cut, a plain one is
    /// untouched (final security review FS-1).
    #[test]
    fn a_point_label_is_scrubbed_and_bounded() {
        assert_eq!(point_label(&named("q")), "q");

        let secret = format!("token={}", "A".repeat(2048));
        let label = point_label(&named(&secret));
        assert_eq!(label, "token=[redacted]");

        let long = "n".repeat(2048);
        let label = point_label(&named(&long));
        assert_eq!(label.len(), MAX_EXCERPT_BYTES);
        assert_eq!(label, "n".repeat(MAX_EXCERPT_BYTES));
    }

    /// A verdict that concluded nothing is always `tentative`: the caller
    /// names the outcome and the detail, and nothing else (Q2-1). Both a
    /// `&str` and a `String` are accepted, so no caller allocates to say
    /// nothing.
    #[test]
    fn no_finding_is_tentative_with_no_evidence_and_no_hint() {
        let v = no_finding(Outcome::Error, "the baseline was refused");
        assert_eq!(v.outcome, Outcome::Error);
        assert_eq!(v.confidence, Confidence::Tentative);
        assert_eq!(v.detail, "the baseline was refused");
        assert_eq!(v.evidence, Evidence::default());
        assert!(v.poc_hint.is_none());

        let owned = no_finding(
            Outcome::Inconclusive,
            format!("{STOPPED} before the baseline"),
        );
        assert_eq!(owned.confidence, Confidence::Tentative);
        assert_eq!(
            owned.detail,
            "the job was cancelled, out of budget or past its deadline before the baseline"
        );
    }

    /// The one spelling of the standing stop reason every check composes
    /// its own sentence from (Q2-2), and its list form, which takes a fourth
    /// reason after a comma (FQ-2). Both are pinned: the second is not
    /// derived from the first by a string edit.
    #[test]
    fn the_stop_reason_is_spelled_once() {
        assert_eq!(
            STOPPED,
            "the job was cancelled, out of budget or past its deadline"
        );
        assert_eq!(
            STOPPED_LIST,
            "the job was cancelled, out of budget, past its deadline"
        );
    }

    fn tally(planned: usize, sent: usize, failed: usize) -> ProbeTally {
        let mut t = ProbeTally::new("canary probes", planned);
        for _ in 0..sent {
            t.attempted();
        }
        for _ in 0..failed {
            t.refused();
        }
        t
    }

    /// A complete run that found nothing is clean, and says what it tried.
    #[test]
    fn a_complete_run_with_nothing_refused_is_clean() {
        let v = tally(3, 3, 0).conclude("nothing matched".to_string());
        assert_eq!(v.outcome, Outcome::Clean);
        assert_eq!(v.detail, "nothing matched");
        assert!(v.poc_hint.is_none());
        assert_eq!(v.evidence.matched, None);
    }

    /// Every attempt refused, with the whole plan attempted, is the target's
    /// failure and the one case that is an `Error`.
    #[test]
    fn a_plan_whose_every_attempt_was_refused_is_an_error() {
        let v = tally(3, 3, 3).conclude("unreachable".to_string());
        assert_eq!(v.outcome, Outcome::Error);
        assert_eq!(v.detail, "every one of the 3 canary probes was refused");
    }

    /// The order of the two clauses: one refused attempt out of three, with
    /// the run stopped, is inconclusive — not an error (Q-M2).
    #[test]
    fn a_run_that_stopped_early_is_inconclusive_even_if_every_attempt_was_refused() {
        let v = tally(3, 1, 1).conclude("unreachable".to_string());
        assert_eq!(v.outcome, Outcome::Inconclusive);
        assert_eq!(
            v.detail,
            "stopped after 1 of 3 canary probes: the job was cancelled, out of budget or past \
             its deadline"
        );
    }

    /// A check with its own cap names it as a fourth reason.
    #[test]
    fn an_extra_stop_reason_is_named_in_the_detail() {
        let v = tally(8, 5, 0)
            .also_stopped_by("this point had spent its 10 probes".to_string())
            .conclude("nothing matched".to_string());
        assert_eq!(v.outcome, Outcome::Inconclusive);
        assert_eq!(
            v.detail,
            "stopped after 5 of 8 canary probes: the job was cancelled, out of budget, past \
             its deadline, or this point had spent its 10 probes"
        );
    }

    /// A run that sent nothing at all is not an error either: there is no
    /// evidence the target refused anything.
    #[test]
    fn a_run_that_sent_nothing_is_inconclusive() {
        let v = tally(3, 0, 0).conclude("nothing matched".to_string());
        assert_eq!(v.outcome, Outcome::Inconclusive);
    }
}
