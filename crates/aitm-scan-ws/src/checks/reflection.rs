//! The `ws-input-reflection` check: a canary placed in a WebSocket field and
//! looked for in the server's reply frames (spec D8.3, plan task 11).
//!
//! The oracle is one probe. A marker that comes back inside a reply frame means
//! the field reaches the server's output; whether `<`, `>` and `'` survive that
//! round trip is what separates an HTML-context reflection from an escaped one.
//! The canary is [`crate::payloads::reflection_canary`] (`<marker><'>`) rather
//! than a quote-bearing one on purpose: a JSON point is re-serialised on the
//! way out, which would escape a `"` and make every JSON point read as
//! "encoded" (plan call 16).
//!
//! Two rules the file must keep:
//!
//! - **An encoded reflection is `Clean`.** A marker that comes back with its
//!   `<`, `>` and `'` HTML-escaped reaches the output but is not exploitable as
//!   written, so it is `Clean`/`Tentative` with a detail that says why (plan
//!   call 36). `Verdict` carries no severity, so the spec's "low otherwise" arm
//!   — reporting it as a low-severity observation — waits on
//!   `Verdict.severity_override`, a T1b follow-up already in the hand-off list.
//! - **Nothing of the server's own text leaves here.** `Evidence.matched` is
//!   the canary or the marker — both scanner constants for this job — so no
//!   cookie, header value or captured message can ride out in a verdict. The
//!   conversation itself stays in the host's held flows, which are store data.

use std::sync::{Arc, OnceLock};
use std::time::Instant;

use aitm_poc::Severity;
use aitm_scan_model::{
    Check, CheckCost, CheckMeta, CheckOrigin, Confidence, Evidence, InsertionKind, InsertionPoint,
    Intensity, LaneKind, Outcome, Payload, PayloadMode, ProbeHost, Technique, Verdict,
};
use futures::future::BoxFuture;

use crate::payloads::{classify_reflection, reflection_canary, Reflection};

/// The catalogue id of this check, also the `check.<id>` verb's suffix.
pub const ID: &str = "ws-input-reflection";

/// Detail for a reflection that came back with its metacharacters intact.
const UNENCODED_DETAIL: &str = "marker reflected with < and > unencoded";

/// Detail for a reflection whose metacharacters the server encoded.
const ENCODED_DETAIL: &str =
    "marker reflected with special characters encoded (not exploitable as written)";

/// Detail for a reply that carried neither the canary nor the marker.
const ABSENT_DETAIL: &str = "the marker did not come back in any reply frame";

/// Reports a WebSocket field whose value the server echoes into a reply frame.
///
/// Stateless: one instance serves every point the scheduler aims it at.
pub struct InputReflection;

/// This check, as the lane registers it.
#[must_use]
pub fn check() -> Arc<dyn Check> {
    Arc::new(InputReflection)
}

/// The catalogue entry, built once.
fn meta() -> &'static CheckMeta {
    static META: OnceLock<CheckMeta> = OnceLock::new();
    META.get_or_init(|| CheckMeta {
        id: ID.to_string(),
        name: "WebSocket input reflected in a reply".to_string(),
        class: "ws-input-reflection".to_string(),
        lanes: vec![LaneKind::Ws],
        kinds: vec![
            InsertionKind::WsJsonValue,
            InsertionKind::WsText,
            InsertionKind::WsFormParam,
        ],
        intensity: Intensity::Light,
        cost: CheckCost::Light,
        technique: Technique::Reflected,
        severity: Severity::Medium,
        confidence_max: Confidence::Certain,
        needs_baseline: false,
        wants_traits: None,
        targets_session: false,
        cwe: Some(79),
        description:
            "Sends a marked canary in a WebSocket field and reports it when the server echoes it \
             back in a reply frame."
                .to_string(),
        remediation: Some(
            "Encode values for the context they are rendered in before echoing them back to a \
             client."
                .to_string(),
        ),
        origin: CheckOrigin::Native,
    })
}

/// Why the check must not probe, if it must not.
///
/// Checked before the payload is built so a stopped job never opens a socket.
fn stop_reason(host: &dyn ProbeHost) -> Option<&'static str> {
    if host.cancelled() {
        Some("cancelled")
    } else if host.budget_left() == 0 {
        Some("budget exhausted")
    } else if host.deadline() <= Instant::now() {
        Some("deadline passed")
    } else {
        None
    }
}

/// A verdict that concluded nothing, carrying only what the check tried to send.
fn inconclusive(detail: String, payload: Option<String>) -> Verdict {
    Verdict {
        outcome: Outcome::Inconclusive,
        confidence: Confidence::Tentative,
        evidence: Evidence {
            payload,
            ..Evidence::default()
        },
        detail,
        poc_hint: None,
    }
}

impl Check for InputReflection {
    fn meta(&self) -> &CheckMeta {
        meta()
    }

    /// One probe: place the canary, read the reply frames, classify the echo.
    ///
    /// The point itself is not read: the scheduler has already matched it
    /// against `kinds`, and the host knows where to place the payload.
    fn run<'a>(
        &'a self,
        _point: &'a InsertionPoint,
        host: &'a dyn ProbeHost,
    ) -> BoxFuture<'a, Verdict> {
        Box::pin(async move {
            if let Some(reason) = stop_reason(host) {
                return inconclusive(reason.to_string(), None);
            }

            let marker = host.marker();
            let canary = reflection_canary(&marker);
            let payload = Payload {
                value: canary.clone(),
                mode: PayloadMode::Replace,
                bytes: None,
            };
            let response = match host.probe(&payload).await {
                Ok(response) => response,
                Err(error) => {
                    // The dialer's error text names the transport failure, never
                    // a header of the request that failed to go out.
                    return inconclusive(format!("connect error: {error}"), Some(canary));
                }
            };

            // The body is the concatenated text replies of the reply window; a
            // frame that is not valid UTF-8 still matches on its ASCII runs.
            let body = String::from_utf8_lossy(&response.body);
            let (outcome, detail, matched) = match classify_reflection(&body, &marker) {
                Reflection::Unencoded => {
                    (Outcome::Vulnerable, UNENCODED_DETAIL, Some(canary.clone()))
                }
                Reflection::Encoded => (Outcome::Clean, ENCODED_DETAIL, None),
                Reflection::Absent => (Outcome::Clean, ABSENT_DETAIL, None),
            };

            Verdict {
                confidence: if outcome == Outcome::Vulnerable {
                    Confidence::Certain
                } else {
                    Confidence::Tentative
                },
                outcome,
                evidence: Evidence {
                    payload: Some(canary),
                    matched,
                    // Empty under `issues_only`: the engine re-records the
                    // conversation from the host's held flows instead (D5).
                    probe_flows: response.flow.into_iter().collect(),
                    ..Evidence::default()
                },
                detail: detail.to_string(),
                // No `ws:` PoC step exists in v2, so a hint would describe a
                // reproduction the runner cannot execute (plan call 19).
                poc_hint: None,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use aitm_core::ByteStream;
    use aitm_scan_model::{
        CheckCost, CheckOrigin, Confidence, InsertionKind, Intensity, JobCtx, LaneKind, Outcome,
        ProbeHost, RecordProbes, Technique,
    };
    use futures::future::BoxFuture;
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    use super::{check, ID};
    use crate::dialer::WsDialer;
    use crate::discover::{discover_flow, IdGen};
    use crate::host::WsProbeHost;
    use crate::testing::{captured_conversation, ws_server, ServerConn, TestJob};
    use crate::transport::WsTransport;

    /// The marker `TestJob` hands out, and the canary the check builds from it.
    const CANARY: &str = "mk7f3a9e<'>";

    /// The mutated frame the `msg` point's probe puts on the wire.
    const PROBE_FRAME: &[u8] = br#"{"msg":"mk7f3a9e<'>","user":"bob"}"#;

    /// A host over the fixture conversation's point named `name`.
    fn host_for(name: &str, job: &Arc<TestJob>, transport: Arc<dyn WsTransport>) -> WsProbeHost {
        let (handshake, ws) = captured_conversation();
        let mut ids = IdGen::new("job-1");
        let found = discover_flow(&ws, &handshake, &mut ids);
        let at = found
            .points
            .iter()
            .position(|point| point.name == name)
            .unwrap_or_else(|| panic!("the fixture has a point named {name}"));
        WsProbeHost::new(
            found.points[at].clone(),
            found.specs[at].1.clone(),
            handshake,
            ws,
            Arc::new(WsDialer::new(transport)),
            Arc::clone(job) as Arc<dyn JobCtx>,
        )
        .expect("the fixture point builds a host")
    }

    /// HTML-escape as the patched build of the seeded target does.
    fn html_escape(text: &str) -> String {
        text.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('\'', "&#x27;")
            .replace('"', "&quot;")
    }

    /// The seeded target's `/ws`: every client text frame is answered with an
    /// echo envelope that repeats `msg` twice, once as a JSON string and once
    /// inside an HTML fragment. `escape` is the patched build.
    ///
    /// Neither the canary nor its escaped form contains a `"` or a `\`, so the
    /// reply is built by interpolation and is still valid JSON — which is what
    /// the target does and what makes the raw echo visibly unencoded.
    async fn seeded_target(conn: ServerConn, escape: bool) {
        let mut ws = conn.ws().await;
        while let Some(Ok(message)) = ws.next().await {
            match message {
                Message::Text(text) => {
                    conn.record(text.as_bytes().to_vec());
                    let msg = serde_json::from_str::<serde_json::Value>(&text)
                        .ok()
                        .and_then(|value| {
                            value
                                .get("msg")
                                .and_then(serde_json::Value::as_str)
                                .map(str::to_string)
                        })
                        .unwrap_or_default();
                    let shown = if escape { html_escape(&msg) } else { msg };
                    let reply =
                        format!(r#"{{"type":"echo","msg":"{shown}","html":"<b>{shown}</b>"}}"#);
                    if ws.send(Message::text(reply)).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    }

    /// The vulnerable build: the field comes back raw.
    async fn vulnerable_target(conn: ServerConn) {
        seeded_target(conn, false).await;
    }

    /// The patched build: the field comes back HTML-escaped.
    async fn patched_target(conn: ServerConn) {
        seeded_target(conn, true).await;
    }

    /// A target that never echoes anything a client sent.
    async fn silent_target(conn: ServerConn) {
        let mut ws = conn.ws().await;
        while let Some(Ok(message)) = ws.next().await {
            match message {
                Message::Text(text) => {
                    conn.record(text.as_bytes().to_vec());
                    if ws.send(Message::text(r#"{"ok":true}"#)).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    }

    /// A transport whose every connect fails, as an unreachable target would.
    struct RefusingTransport;

    impl WsTransport for RefusingTransport {
        fn connect<'a>(
            &'a self,
            _host: &'a str,
            _port: u16,
            _tls: bool,
            _sni: &'a str,
        ) -> BoxFuture<'a, anyhow::Result<ByteStream>> {
            Box::pin(async { Err(anyhow::anyhow!("connection refused")) })
        }
    }

    #[test]
    fn meta_is_the_catalogue_entry() {
        let check = check();
        let meta = check.meta();

        assert_eq!(ID, "ws-input-reflection");
        assert_eq!(meta.id, "ws-input-reflection");
        assert_eq!(meta.name, "WebSocket input reflected in a reply");
        assert_eq!(meta.class, "ws-input-reflection");
        assert_eq!(meta.lanes, vec![LaneKind::Ws]);
        assert_eq!(
            meta.kinds,
            vec![
                InsertionKind::WsJsonValue,
                InsertionKind::WsText,
                InsertionKind::WsFormParam
            ]
        );
        assert_eq!(meta.intensity, Intensity::Light);
        assert_eq!(meta.cost, CheckCost::Light);
        assert_eq!(meta.technique, Technique::Reflected);
        assert_eq!(meta.severity, aitm_poc::Severity::Medium);
        assert_eq!(meta.confidence_max, Confidence::Certain);
        assert!(!meta.needs_baseline);
        assert_eq!(meta.wants_traits, None);
        assert!(!meta.targets_session);
        assert_eq!(meta.cwe, Some(79));
        assert_eq!(meta.origin, CheckOrigin::Native);
        assert!(!meta.description.is_empty());
        assert!(meta.remediation.is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unencoded_reflection_is_certain() {
        let (transport, log) = ws_server(None, vulnerable_target);
        let job = TestJob::new(100);
        let host = host_for("msg", &job, transport as Arc<dyn WsTransport>);
        let point = host.point().clone();

        let verdict = check().run(&point, &host as &dyn ProbeHost).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Vulnerable, Confidence::Certain)
        );
        assert_eq!(verdict.detail, "marker reflected with < and > unencoded");
        assert!(verdict.detail.contains("unencoded"), "{}", verdict.detail);
        assert_eq!(verdict.evidence.payload.as_deref(), Some(CANARY));
        assert_eq!(verdict.evidence.matched.as_deref(), Some(CANARY));
        assert_eq!(verdict.poc_hint, None, "no WS PoC step exists in v2");
        assert_eq!(
            log.received().last().map(Vec::as_slice),
            Some(PROBE_FRAME),
            "the canary is placed at the msg leaf and sent as the last frame"
        );
        let shown = format!("{verdict:?}");
        assert!(
            !shown.contains("s3cr3t-cookie"),
            "the replayed cookie must not reach a verdict: {shown}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn encoded_reflection_is_clean() {
        let (transport, _log) = ws_server(None, patched_target);
        let job = TestJob::new(100);
        let host = host_for("msg", &job, transport as Arc<dyn WsTransport>);
        let point = host.point().clone();

        let verdict = check().run(&point, &host as &dyn ProbeHost).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Clean, Confidence::Tentative),
            "an HTML-escaped reflection is not a vulnerability (plan call 36)"
        );
        assert_eq!(
            verdict.detail,
            "marker reflected with special characters encoded (not exploitable as written)"
        );
        assert_eq!(verdict.evidence.payload.as_deref(), Some(CANARY));
        assert_eq!(
            verdict.evidence.matched, None,
            "a clean verdict evidences no match"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn no_reflection_is_clean() {
        let (transport, log) = ws_server(None, silent_target);
        let job = TestJob::new(100);
        let host = host_for("msg", &job, transport as Arc<dyn WsTransport>);
        let point = host.point().clone();

        let verdict = check().run(&point, &host as &dyn ProbeHost).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Clean, Confidence::Tentative)
        );
        assert_eq!(verdict.evidence.matched, None);
        assert_eq!(
            log.received().last().map(Vec::as_slice),
            Some(PROBE_FRAME),
            "a clean verdict still means the canary was sent"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn budget_zero_is_inconclusive() {
        let (transport, log) = ws_server(None, vulnerable_target);
        let job = TestJob::new(0);
        let host = host_for("msg", &job, transport as Arc<dyn WsTransport>);
        let point = host.point().clone();

        let verdict = check().run(&point, &host as &dyn ProbeHost).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Inconclusive, Confidence::Tentative)
        );
        assert_eq!(verdict.detail, "budget exhausted");
        assert_eq!(log.connections(), 0, "no socket is opened without budget");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cancelled_is_inconclusive() {
        let (transport, log) = ws_server(None, vulnerable_target);
        let job = TestJob::new(100);
        let host = host_for("msg", &job, transport as Arc<dyn WsTransport>);
        let point = host.point().clone();
        job.cancel();

        let verdict = check().run(&point, &host as &dyn ProbeHost).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Inconclusive, Confidence::Tentative)
        );
        assert_eq!(verdict.detail, "cancelled");
        assert_eq!(log.connections(), 0, "no socket is opened after a cancel");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn connect_error_is_inconclusive() {
        let job = TestJob::new(100);
        let host = host_for(
            "msg",
            &job,
            Arc::new(RefusingTransport) as Arc<dyn WsTransport>,
        );
        let point = host.point().clone();

        let verdict = check().run(&point, &host as &dyn ProbeHost).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Inconclusive, Confidence::Tentative)
        );
        assert!(
            verdict.detail.starts_with("connect error: "),
            "{}",
            verdict.detail
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_recorded_probe_links_its_flow() {
        let (transport, _log) = ws_server(None, vulnerable_target);
        let job = TestJob::with(100, |profile| {
            profile.http.record_probes = RecordProbes::All;
        });
        let host = host_for("msg", &job, transport as Arc<dyn WsTransport>);
        let point = host.point().clone();

        let verdict = check().run(&point, &host as &dyn ProbeHost).await;

        assert_eq!(verdict.outcome, Outcome::Vulnerable);
        assert_eq!(
            verdict.evidence.probe_flows.len(),
            1,
            "a recorded probe conversation is linked from the evidence"
        );
        assert_eq!(verdict.evidence.baseline_flow, None, "no baseline is taken");
    }
}
