//! The `ws-oversize-frame` check — written by task 15 of the T4 plan.
//!
//! One bounded frame, sent once: the probe host pads the point's chosen frame
//! to exactly `min(2 x largest observed client frame, profile.ws.max_frame_bytes)`
//! bytes (spec D8.3 "Checks"; the host owns the sizing because a check holds
//! only a `&dyn ProbeHost` and cannot see the captured flow — T4 plan call 21).
//! This is an observation of one frame, never a flood.
//!
//! What the server does with it is read back off `ProbeResponse.ws_frames`,
//! which is the whole surface a check has (plan call 18):
//!
//! | What came back | Verdict |
//! |---|---|
//! | `Close` with code 1009 or 1002 | `Clean` — the limit is enforced |
//! | a `Text`/`Binary` reply | `Vulnerable`/`Firm` — the frame was processed |
//! | nothing, no `Close`, window ended early | `Vulnerable`/`Firm` — dropped without a Close |
//! | nothing, the window elapsed | `Inconclusive` |
//!
//! The drop arm stays `Vulnerable(Info, Firm)` and names itself a robustness
//! observation (T4 session decision 5). `evidence.payload` describes the frame
//! in words and never carries the padding itself.

use std::sync::{Arc, OnceLock};

use aitm_scan_model::{
    Check, CheckCost, CheckMeta, CheckOrigin, Confidence, Evidence, Frame, FrameKind,
    InsertionKind, InsertionPoint, Intensity, LaneKind, Outcome, ProbeHost, Technique, Verdict,
};
use futures::future::BoxFuture;

use crate::checks::common;

use crate::host::pad_payload;

/// The catalogue identifier, also the manual `check.<id>` verb's suffix.
pub const ID: &str = "ws-oversize-frame";

/// What `evidence.payload` says about the frame that was sent.
///
/// The padding itself is never evidence: the exact frame is in the host's
/// `held_flows()` for the engine to re-record.
const PAYLOAD_DESCRIPTION: &str =
    "oversized frame (2 x largest observed, capped by max_frame_bytes)";

/// The close codes that mean the server enforced a frame or message limit:
/// 1009 `Message Too Big` and 1002 `Protocol Error` (RFC 6455 section 7.4.1).
const LIMIT_CLOSE_CODES: [u16; 2] = [1009, 1002];

/// Whether the endpoint enforces a maximum WebSocket frame size.
pub struct OversizeFrame;

/// The `ws-oversize-frame` check, as the lane registers it.
#[must_use]
pub fn check() -> Arc<dyn Check> {
    Arc::new(OversizeFrame)
}

/// The catalogue entry, built once.
fn meta() -> &'static CheckMeta {
    static META: OnceLock<CheckMeta> = OnceLock::new();
    META.get_or_init(|| CheckMeta {
        id: ID.to_string(),
        name: "Oversized WebSocket frame accepted".to_string(),
        class: "ws-oversize-frame".to_string(),
        lanes: vec![LaneKind::Ws],
        kinds: vec![
            InsertionKind::WsText,
            InsertionKind::WsJsonValue,
            InsertionKind::WsBinary,
        ],
        intensity: Intensity::Medium,
        cost: CheckCost::Light,
        technique: Technique::Malformed,
        severity: aitm_poc::Severity::Info,
        confidence_max: Confidence::Firm,
        needs_baseline: false,
        wants_traits: None,
        targets_session: false,
        cwe: Some(400),
        description: "Sends one frame padded to twice the largest frame the capture observed, \
                      capped by the profile's maximum frame size, and reports whether the \
                      endpoint enforces a frame-size limit."
            .to_string(),
        remediation: Some(
            "Cap the frame and message size the endpoint will buffer and close an oversized \
             conversation with code 1009 instead of processing or dropping it."
                .to_string(),
        ),
        origin: CheckOrigin::Native,
    })
}

impl Check for OversizeFrame {
    fn meta(&self) -> &CheckMeta {
        meta()
    }

    fn run<'a>(
        &'a self,
        _point: &'a InsertionPoint,
        host: &'a dyn ProbeHost,
    ) -> BoxFuture<'a, Verdict> {
        Box::pin(async move {
            if let Some(reason) = common::stop_reason(host) {
                return common::inconclusive(reason, Vec::new());
            }

            let response = match host.probe(&pad_payload()).await {
                Ok(response) => response,
                // The dialer's error text names hosts, ports and timeouts, never
                // a header value, so it is safe to put in front of an operator.
                Err(err) => return common::connect_error(&err, Vec::new()),
            };

            let evidence = Evidence {
                payload: Some(PAYLOAD_DESCRIPTION.to_string()),
                probe_flows: response.flow.into_iter().collect(),
                ..Evidence::default()
            };
            let frames = common::reply_frames(&response);
            let limit_close = frames
                .iter()
                .filter(|frame| frame.kind == FrameKind::Close)
                .filter_map(close_code)
                .find(|code| LIMIT_CLOSE_CODES.contains(code));
            let replied = frames
                .iter()
                .any(|frame| matches!(frame.kind, FrameKind::Text | FrameKind::Binary));
            let closed = frames.iter().any(|frame| frame.kind == FrameKind::Close);

            if let Some(code) = limit_close {
                return common::clean(
                    format!("server closed with {code} (frame-size limit enforced)"),
                    evidence,
                );
            }
            if replied {
                return verdict(
                    Outcome::Vulnerable,
                    Confidence::Firm,
                    "no frame-size limit enforced: the oversized frame was processed".to_string(),
                    evidence,
                );
            }
            // No reply and no Close, with the window cut short: the only thing
            // that ends collection early is the peer going away (the dial for a
            // pad probe reads above the pad target, so our own reader cannot be
            // the one that gave up — T4 plan call 31).
            if !closed && response.elapsed_ms < host.profile().ws.reply_window_ms {
                return verdict(
                    Outcome::Vulnerable,
                    Confidence::Firm,
                    "connection dropped without a Close frame after the oversized frame"
                        .to_string(),
                    evidence,
                );
            }
            verdict(
                Outcome::Inconclusive,
                Confidence::Tentative,
                "no reaction within the reply window".to_string(),
                evidence,
            )
        })
    }
}

/// The close code a `Close` frame carries, `None` when its payload is shorter
/// than the two big-endian bytes RFC 6455 section 5.5.1 puts first.
fn close_code(frame: &Frame) -> Option<u16> {
    match frame.payload.get(..2) {
        Some(&[high, low]) => Some(u16::from_be_bytes([high, low])),
        _ => None,
    }
}

/// Assemble a verdict. No WS check carries a PoC hint in v2 (plan call 19).
fn verdict(
    outcome: Outcome,
    confidence: Confidence,
    detail: String,
    evidence: Evidence,
) -> Verdict {
    Verdict {
        outcome,
        confidence,
        evidence,
        detail,
        poc_hint: None,
    }
}

#[cfg(test)]
mod tests {

    use aitm_scan_model::{
        CheckCost, CheckOrigin, Confidence, InsertionKind, Intensity, LaneKind, Outcome, Technique,
    };
    use futures::{SinkExt, StreamExt};
    use tokio::io::AsyncWriteExt;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
    use tokio_tungstenite::tungstenite::protocol::CloseFrame;
    use tokio_tungstenite::tungstenite::Message;

    use super::check;
    use crate::testing::{echo_handler, point_and_host_for, ws_server, ServerConn, TestJob};

    /// The fixture's chosen client frame, `{"msg":"hi","user":"bob"}`.
    const CHOSEN_LEN: usize = 25;

    /// The byte length the pad targets: twice the largest captured client frame.
    const PADDED_LEN: usize = 2 * CHOSEN_LEN;

    /// The fixture's `msg` point and a host over it, as the lane would build them.
    /// A server that answers small frames and closes with 1009 above 40 bytes.
    async fn closes_1009_above_40(conn: ServerConn) {
        let mut ws = conn.ws().await;
        while let Some(Ok(message)) = ws.next().await {
            match message {
                Message::Text(text) => {
                    conn.record(text.as_bytes().to_vec());
                    if text.len() > 40 {
                        let _ = ws
                            .send(Message::Close(Some(CloseFrame {
                                code: CloseCode::Size,
                                reason: "message too big".into(),
                            })))
                            .await;
                        break;
                    }
                    if ws
                        .send(Message::text(format!("echo:{text}")))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    }

    /// A server that answers small frames and drops the socket above 40 bytes,
    /// without a Close frame: the client sees EOF in the middle of the window.
    async fn drops_above_40(conn: ServerConn) {
        let mut ws = conn.ws().await;
        while let Some(Ok(message)) = ws.next().await {
            match message {
                Message::Text(text) => {
                    conn.record(text.as_bytes().to_vec());
                    if text.len() > 40 {
                        let _ = ws.get_mut().shutdown().await;
                        break;
                    }
                    if ws
                        .send(Message::text(format!("echo:{text}")))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    }

    /// A server that reads every frame and never answers one.
    async fn never_replies(conn: ServerConn) {
        let mut ws = conn.ws().await;
        while let Some(Ok(message)) = ws.next().await {
            match message {
                Message::Text(text) => conn.record(text.as_bytes().to_vec()),
                Message::Close(_) => break,
                _ => {}
            }
        }
    }

    #[test]
    fn meta_is_the_catalogue_entry() {
        let check = check();
        let meta = check.meta();

        assert_eq!(meta.id, "ws-oversize-frame");
        assert_eq!(meta.class, "ws-oversize-frame");
        assert_eq!(meta.lanes, vec![LaneKind::Ws]);
        assert_eq!(
            meta.kinds,
            vec![
                InsertionKind::WsText,
                InsertionKind::WsJsonValue,
                InsertionKind::WsBinary
            ]
        );
        assert_eq!(meta.intensity, Intensity::Medium);
        assert_eq!(meta.cost, CheckCost::Light);
        assert_eq!(meta.technique, Technique::Malformed);
        assert_eq!(meta.severity, aitm_poc::Severity::Info);
        assert_eq!(meta.confidence_max, Confidence::Firm);
        assert!(!meta.needs_baseline, "one probe, no baseline");
        assert!(!meta.targets_session);
        assert_eq!(meta.cwe, Some(400));
        assert_eq!(meta.origin, CheckOrigin::Native);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn vulnerable_server_processes_oversize_frame() {
        let (transport, log) = ws_server(None, echo_handler);
        let job = TestJob::new(100);
        let (point, host) = point_and_host_for("msg", &job, transport);

        let verdict = check().run(&point, &host).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Vulnerable, Confidence::Firm),
            "an echoed oversize frame is a processed oversize frame: {verdict:?}"
        );
        assert!(
            verdict.detail.contains("no frame-size limit"),
            "detail: {}",
            verdict.detail
        );
        assert_eq!(
            log.received().get(1).map(Vec::len),
            Some(PADDED_LEN),
            "exactly one frame, padded to twice the largest observed client frame"
        );
        assert_eq!(log.connections(), 1, "the check spends exactly one dial");
        assert!(
            !format!("{verdict:?}").contains("s3cr3t-cookie"),
            "no captured credential may reach a verdict: {verdict:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patched_server_closes_1009() {
        let (transport, _log) = ws_server(None, closes_1009_above_40);
        let job = TestJob::new(100);
        let (point, host) = point_and_host_for("msg", &job, transport);

        let verdict = check().run(&point, &host).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Clean, Confidence::Tentative),
            "a 1009 close is the frame-size limit being enforced: {verdict:?}"
        );
        assert!(
            verdict.detail.contains("1009"),
            "detail names the close code: {}",
            verdict.detail
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dropped_connection_is_flagged() {
        let (transport, _log) = ws_server(None, drops_above_40);
        let job = TestJob::new(100);
        let (point, host) = point_and_host_for("msg", &job, transport);

        let verdict = check().run(&point, &host).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Vulnerable, Confidence::Firm),
            "a drop with no Close frame is a robustness observation: {verdict:?}"
        );
        assert!(
            verdict.detail.contains("dropped"),
            "detail: {}",
            verdict.detail
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn silence_is_inconclusive() {
        let (transport, _log) = ws_server(None, never_replies);
        let job = TestJob::with(100, |profile| {
            profile.ws.reply_window_ms = 300;
        });
        let (point, host) = point_and_host_for("msg", &job, transport);

        let verdict = check().run(&point, &host).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Inconclusive, Confidence::Tentative),
            "a silent window says nothing either way: {verdict:?}"
        );
        assert!(
            verdict.detail.contains("no reaction"),
            "detail: {}",
            verdict.detail
        );
    }
}
