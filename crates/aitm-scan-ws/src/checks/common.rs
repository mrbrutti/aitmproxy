//! The pieces every native WebSocket check shares.
//!
//! The eight checks were written one per task and each grew its own copy of the
//! same four or five helpers: the pre-probe stop test, the `Inconclusive` and
//! `Clean` verdict shapes, the dialer-error verdict and "the first data frame
//! of a reply". They are gathered here so the texts an operator reads — the
//! three stop reasons and `connect error: …` — are written once and a ninth
//! check inherits them (quality finding Q4).
//!
//! Two rules these helpers carry for every check:
//!
//! - **`Inconclusive` and `Clean` are `Tentative`.** Only a positive finding
//!   raises confidence, and it does so in the check that made it.
//! - **No WS check carries a PoC hint.** No `ws:` PoC step exists in v2, so a
//!   hint would describe a reproduction the runner cannot execute (plan call
//!   19).

use std::time::Instant;

use aitm_scan_model::{
    Confidence, Evidence, FlowRef, Frame, FrameKind, Outcome, ProbeHost, Verdict,
};

/// Why the check must send nothing (more), or `None` while it may probe.
///
/// Polled before the first dial and again in every gap between probes, so a
/// cancel or an exhausted budget ends a run at the next gap rather than
/// several dials later. The three texts are what the verdict's `detail` reads.
pub(crate) fn stop_reason(host: &dyn ProbeHost) -> Option<&'static str> {
    if host.cancelled() {
        return Some("cancelled");
    }
    if host.budget_left() == 0 {
        return Some("budget exhausted");
    }
    if host.deadline() <= Instant::now() {
        return Some("deadline passed");
    }
    None
}

/// A verdict that concluded nothing, carrying the probes that did run.
pub(crate) fn inconclusive(detail: impl Into<String>, probe_flows: Vec<FlowRef>) -> Verdict {
    Verdict {
        outcome: Outcome::Inconclusive,
        confidence: Confidence::Tentative,
        evidence: Evidence {
            probe_flows,
            ..Evidence::default()
        },
        detail: detail.into(),
        poc_hint: None,
    }
}

/// The verdict for a dialer error: `Inconclusive`, naming the failure.
///
/// The dialer's error text names the authority, the port and the transport
/// failure and never a header value (the probe host's contract), so it is safe
/// in front of an operator.
pub(crate) fn connect_error(e: &anyhow::Error) -> Verdict {
    inconclusive(format!("connect error: {e}"), Vec::new())
}

/// A `Clean` verdict, which is `Tentative` by the common check shape.
pub(crate) fn clean(detail: impl Into<String>, evidence: Evidence) -> Verdict {
    Verdict {
        outcome: Outcome::Clean,
        confidence: Confidence::Tentative,
        evidence,
        detail: detail.into(),
        poc_hint: None,
    }
}

/// The first Text or Binary frame of a reply; a control frame is never the
/// oracle (a Ping or a Close says nothing about what the server did with the
/// payload).
pub(crate) fn first_data_frame(frames: &[Frame]) -> Option<&Frame> {
    frames
        .iter()
        .find(|frame| matches!(frame.kind, FrameKind::Text | FrameKind::Binary))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use aitm_scan_model::{Confidence, Evidence, Frame, FrameKind, Outcome};

    use super::{clean, connect_error, first_data_frame, inconclusive, stop_reason};
    use crate::testing::{host_for, DuplexTransport, TestJob};

    /// A frame of `kind` with no payload.
    fn frame(kind: FrameKind) -> Frame {
        Frame {
            kind,
            payload: Vec::new(),
        }
    }

    #[test]
    fn stop_reason_names_the_three_stops_in_order() {
        let transport = DuplexTransport::new(|_| {});

        let running = TestJob::new(10);
        let host = host_for("msg", &running, Arc::clone(&transport));
        assert_eq!(stop_reason(&host), None);

        let cancelled = TestJob::new(10);
        cancelled.cancel();
        let host = host_for("msg", &cancelled, Arc::clone(&transport));
        assert_eq!(stop_reason(&host), Some("cancelled"));

        let broke = TestJob::new(0);
        let host = host_for("msg", &broke, Arc::clone(&transport));
        assert_eq!(stop_reason(&host), Some("budget exhausted"));

        let late = TestJob::new(10);
        late.set_deadline(Instant::now() - Duration::from_secs(1));
        let host = host_for("msg", &late, transport);
        assert_eq!(stop_reason(&host), Some("deadline passed"));
    }

    #[test]
    fn verdict_shapes() {
        let nothing = inconclusive("cancelled", Vec::new());
        assert_eq!(nothing.outcome, Outcome::Inconclusive);
        assert_eq!(nothing.confidence, Confidence::Tentative);
        assert_eq!(nothing.detail, "cancelled");
        assert_eq!(nothing.poc_hint, None);

        let failed = connect_error(&anyhow::anyhow!("no route to host"));
        assert_eq!(failed.outcome, Outcome::Inconclusive);
        assert_eq!(failed.detail, "connect error: no route to host");

        let nothing_found = clean("no signature", Evidence::default());
        assert_eq!(nothing_found.outcome, Outcome::Clean);
        assert_eq!(nothing_found.confidence, Confidence::Tentative);
        assert_eq!(nothing_found.detail, "no signature");
    }

    #[test]
    fn first_data_frame_skips_control_frames() {
        assert!(first_data_frame(&[]).is_none());
        assert!(first_data_frame(&[frame(FrameKind::Ping), frame(FrameKind::Close)]).is_none());
        let frames = [
            frame(FrameKind::Ping),
            frame(FrameKind::Binary),
            frame(FrameKind::Text),
        ];
        assert_eq!(
            first_data_frame(&frames).map(|frame| frame.kind),
            Some(FrameKind::Binary)
        );
    }
}
