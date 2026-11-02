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
    Confidence, Evidence, FlowRef, Frame, FrameKind, Outcome, ProbeHost, ProbeResponse, Verdict,
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
        location: None,
        more: Vec::new(),
    }
}

/// The verdict for a dialer error: `Inconclusive`, naming the failure and
/// carrying the probes that did run before it.
///
/// `probe_flows` is the check's flows so far, so a check never has to reach
/// into the verdict it was just handed to put them back (quality finding N4).
/// The dialer's error text names the authority, the port and the transport
/// failure and never a header value, a path or a query (the probe host's
/// contract, security finding S9), so it is safe in front of an operator.
pub(crate) fn connect_error(e: &anyhow::Error, probe_flows: Vec<FlowRef>) -> Verdict {
    inconclusive(format!("connect error: {e}"), probe_flows)
}

/// A `Clean` verdict, which is `Tentative` by the common check shape.
pub(crate) fn clean(detail: impl Into<String>, evidence: Evidence) -> Verdict {
    Verdict {
        outcome: Outcome::Clean,
        confidence: Confidence::Tentative,
        evidence,
        detail: detail.into(),
        poc_hint: None,
        location: None,
        more: Vec::new(),
    }
}

/// The frames `response`'s reply window collected; empty when it collected
/// none, so no check writes `ws_frames.as_deref().unwrap_or(&[])` itself
/// (quality finding N4).
pub(crate) fn reply_frames(response: &ProbeResponse) -> &[Frame] {
    response.ws_frames.as_deref().unwrap_or_default()
}

/// The first Text or Binary frame of `response`; a control frame is never the
/// oracle (a Ping or a Close says nothing about what the server did with the
/// payload).
pub(crate) fn first_data_frame(response: &ProbeResponse) -> Option<&Frame> {
    reply_frames(response)
        .iter()
        .find(|frame| matches!(frame.kind, FrameKind::Text | FrameKind::Binary))
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use aitm_scan_model::{
        Confidence, Evidence, FlowRef, Frame, FrameKind, Outcome, ProbeResponse,
    };

    use super::{clean, connect_error, first_data_frame, inconclusive, reply_frames, stop_reason};
    use crate::testing::{host_for, DuplexTransport, TestJob};

    /// A frame of `kind` with no payload.
    fn frame(kind: FrameKind) -> Frame {
        Frame {
            kind,
            payload: Vec::new(),
        }
    }

    /// A probe reply that collected `frames` (or no reply window at all).
    fn response(frames: Option<Vec<Frame>>) -> ProbeResponse {
        ProbeResponse {
            status: Some(101),
            headers: Vec::new(),
            body: Vec::new(),
            elapsed_ms: 1,
            flow: None,
            ws_frames: frames,
            l4: None,
        }
    }

    #[test]
    fn stop_reason_names_the_three_stops_in_order() {
        let transport = DuplexTransport::new(|_| {});

        let running = TestJob::new(10);
        let host = host_for("msg", &running, transport.clone());
        assert_eq!(stop_reason(&host), None);

        let cancelled = TestJob::new(10);
        cancelled.cancel();
        let host = host_for("msg", &cancelled, transport.clone());
        assert_eq!(stop_reason(&host), Some("cancelled"));

        let broke = TestJob::new(0);
        let host = host_for("msg", &broke, transport.clone());
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

        let failed = connect_error(
            &anyhow::anyhow!("no route to host"),
            vec![FlowRef(aitm_core::FlowId::new())],
        );
        assert_eq!(failed.outcome, Outcome::Inconclusive);
        assert_eq!(failed.detail, "connect error: no route to host");
        assert_eq!(
            failed.evidence.probe_flows.len(),
            1,
            "the probes that ran before the failure stay on the verdict"
        );

        let nothing_found = clean("no signature", Evidence::default());
        assert_eq!(nothing_found.outcome, Outcome::Clean);
        assert_eq!(nothing_found.confidence, Confidence::Tentative);
        assert_eq!(nothing_found.detail, "no signature");
    }

    #[test]
    fn first_data_frame_skips_control_frames() {
        assert!(first_data_frame(&response(None)).is_none());
        assert!(first_data_frame(&response(Some(Vec::new()))).is_none());
        assert!(first_data_frame(&response(Some(vec![
            frame(FrameKind::Ping),
            frame(FrameKind::Close)
        ])))
        .is_none());
        let reply = response(Some(vec![
            frame(FrameKind::Ping),
            frame(FrameKind::Binary),
            frame(FrameKind::Text),
        ]));
        assert_eq!(
            first_data_frame(&reply).map(|frame| frame.kind),
            Some(FrameKind::Binary)
        );
    }

    #[test]
    fn reply_frames_reads_an_absent_window_as_none_collected() {
        assert_eq!(reply_frames(&response(None)).len(), 0);
        assert_eq!(
            reply_frames(&response(Some(vec![frame(FrameKind::Text)]))).len(),
            1
        );
    }
}
