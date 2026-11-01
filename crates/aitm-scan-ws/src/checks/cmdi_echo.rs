//! The `ws-cmdi-echo` check — written by task 14 of the T4 plan.
//!
//! One field of a WebSocket message is replaced, in turn, with five shell
//! command-separator forms wrapped around `echo <marker>` (spec D8.3, "Checks";
//! plan call 6). If the field reaches a shell, the separator ends the intended
//! command and `echo` prints the scanner's own marker: the reply then carries
//! the marker **without** the literal payload text. A target that merely
//! reflects its input sends the payload back verbatim, which is why
//! [`crate::payloads::cmdi_hit`] requires the marker present and the payload
//! absent — reflection is `ws-input-reflection`'s finding, not this one's.
//!
//! The probe is inert by construction: `echo` prints a token this scan
//! generated and does nothing else. Nothing is read, written or fetched on the
//! target, and no payload here carries a second command.
//!
//! Evidence is scanner-owned: `matched` is the marker and `payload` is the form
//! that was sent, so no server text — and therefore no cookie or header value —
//! can travel in a verdict (the redaction rule).

use std::sync::{Arc, OnceLock};
use std::time::Instant;

use aitm_scan_model::{
    Check, CheckCost, CheckMeta, CheckOrigin, Confidence, Evidence, FlowRef, InsertionKind,
    InsertionPoint, Intensity, LaneKind, Outcome, Payload, PayloadMode, ProbeHost, Technique,
    Verdict,
};
use futures::future::BoxFuture;

use crate::payloads::{cmdi_hit, cmdi_probes};

/// The catalogue id of this check, also its manual `check.<id>` verb suffix.
pub const ID: &str = "ws-cmdi-echo";

/// Detail text of a vulnerable verdict; also what the operator reads first.
const HIT_DETAIL: &str = "echo of the marker without the literal payload";

/// `ws-cmdi-echo`: an `echo <marker>` command separator placed in a field.
///
/// Stateless; one instance serves every point of every job.
pub struct CmdiEcho;

/// This check as the lane registers it.
#[must_use]
pub fn check() -> Arc<dyn Check> {
    Arc::new(CmdiEcho)
}

/// The catalogue entry, built once (plan task 14, "Meta").
fn meta() -> &'static CheckMeta {
    static META: OnceLock<CheckMeta> = OnceLock::new();
    META.get_or_init(|| CheckMeta {
        id: ID.to_string(),
        name: "OS command injection echo via WebSocket".to_string(),
        class: "cmdi".to_string(),
        lanes: vec![LaneKind::Ws],
        kinds: vec![
            InsertionKind::WsJsonValue,
            InsertionKind::WsText,
            InsertionKind::WsFormParam,
        ],
        intensity: Intensity::Medium,
        cost: CheckCost::Medium,
        technique: Technique::Reflected,
        severity: aitm_poc::Severity::High,
        confidence_max: Confidence::Firm,
        needs_baseline: false,
        wants_traits: None,
        targets_session: false,
        cwe: Some(78),
        description: "Replaces a WebSocket field with shell command separators wrapping \
                      `echo <marker>` and reports the field as command-injectable when a reply \
                      carries the marker without the payload that asked for it."
            .to_string(),
        remediation: Some(
            "Never pass a WebSocket message field to a shell; call the program directly with an \
             argument vector, or validate the field against a strict allowlist."
                .to_string(),
        ),
        origin: CheckOrigin::Native,
    })
}

impl Check for CmdiEcho {
    fn meta(&self) -> &CheckMeta {
        meta()
    }

    fn run<'a>(
        &'a self,
        _point: &'a InsertionPoint,
        host: &'a dyn ProbeHost,
    ) -> BoxFuture<'a, Verdict> {
        Box::pin(async move {
            let marker = host.marker();
            let mut flows: Vec<FlowRef> = Vec::new();

            for payload in cmdi_probes(&marker) {
                // Re-checked before every form, not once: the budget, the
                // deadline and the cancel flag are the job's and move under us.
                if let Some(reason) = stop_reason(host) {
                    return inconclusive(reason, flows);
                }

                let probe = Payload {
                    value: payload.clone(),
                    mode: PayloadMode::Replace,
                    bytes: None,
                };
                let response = match host.probe(&probe).await {
                    Ok(response) => response,
                    // The dialer's error text names the transport failure and
                    // never a header value (plan tasks 9-16, "Shape").
                    Err(error) => return inconclusive(format!("connect error: {error}"), flows),
                };
                flows.extend(response.flow);

                // Lossy is right here: a shell's output is bytes, and a
                // replacement character cannot forge the ASCII marker.
                let body = String::from_utf8_lossy(&response.body);
                if cmdi_hit(&body, &payload, &marker) {
                    return Verdict {
                        outcome: Outcome::Vulnerable,
                        confidence: Confidence::Firm,
                        evidence: Evidence {
                            payload: Some(payload),
                            matched: Some(marker),
                            probe_flows: flows,
                            ..Evidence::default()
                        },
                        detail: HIT_DETAIL.to_string(),
                        // No `ws:` PoC step exists in v2, so a hint would
                        // describe a reproduction the runner cannot run
                        // (plan call 19).
                        poc_hint: None,
                    };
                }
            }

            Verdict {
                outcome: Outcome::Clean,
                confidence: Confidence::Tentative,
                evidence: Evidence {
                    probe_flows: flows,
                    ..Evidence::default()
                },
                detail: "no reply carried the marker without the payload that asked for it"
                    .to_string(),
                poc_hint: None,
            }
        })
    }
}

/// Why the check must send nothing more, or `None` while it may probe.
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

/// A verdict that concludes nothing, keeping the flows already produced.
fn inconclusive(detail: impl Into<String>, flows: Vec<FlowRef>) -> Verdict {
    Verdict {
        outcome: Outcome::Inconclusive,
        confidence: Confidence::Tentative,
        evidence: Evidence {
            probe_flows: flows,
            ..Evidence::default()
        },
        detail: detail.into(),
        poc_hint: None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use aitm_core::ByteStream;
    use aitm_scan_model::{
        CheckCost, CheckOrigin, Confidence, InsertionKind, Intensity, JobCtx, LaneKind, Outcome,
        ProbeHost, Technique,
    };
    use futures::future::BoxFuture;
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    use super::{check, ID};
    use crate::dialer::WsDialer;
    use crate::discover::{discover_flow, IdGen};
    use crate::host::WsProbeHost;
    use crate::testing::{captured_conversation, echo_handler, ws_server, ServerConn, TestJob};
    use crate::transport::WsTransport;

    /// A probe host over the fixture conversation's `msg` JSON point.
    fn host_for(job: &Arc<TestJob>, transport: Arc<dyn WsTransport>) -> WsProbeHost {
        let (handshake, ws) = captured_conversation();
        let mut ids = IdGen::new("job-1");
        let found = discover_flow(&ws, &handshake, &mut ids);
        let at = found
            .points
            .iter()
            .position(|point| point.name == "msg")
            .expect("the fixture has a point named msg");
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

    /// The seeded vulnerable target: the `msg` field reaches a shell, so
    /// `;echo <text>` prints `<text>` and nothing else — the payload's own
    /// characters never come back.
    fn shell_output(frame: &str) -> Option<String> {
        let value: serde_json::Value = serde_json::from_str(frame).ok()?;
        let msg = value.get("msg")?.as_str()?;
        let printed = msg.split_once(";echo ")?.1;
        Some(format!("{printed}\n"))
    }

    /// The vulnerable handler: a frame whose `msg` carries `;echo ` is answered
    /// with the command's output, any other frame with a plain acknowledgement.
    async fn shell_handler(conn: ServerConn) {
        let mut ws = conn.ws().await;
        while let Some(Ok(message)) = ws.next().await {
            match message {
                Message::Text(text) => {
                    conn.record(text.as_bytes().to_vec());
                    let reply = shell_output(&text).unwrap_or_else(|| r#"{"ok":true}"#.to_string());
                    if ws.send(Message::text(reply)).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    }

    /// The minimal HTML escaping the patched seed applies to the echoed field:
    /// `& < > " '`, in that order. Spelled out here rather than reused from
    /// `payloads` so the server side of this test cannot agree with a wrong
    /// escaper in the matcher it is testing.
    fn seed_escape(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            match c {
                '&' => out.push_str("&amp;"),
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '"' => out.push_str("&quot;"),
                '\'' => out.push_str("&#x27;"),
                _ => out.push(c),
            }
        }
        out
    }

    /// The patched handler, modelled on T10's Patched `/ws` seed: it reads
    /// `msg`, HTML-escapes it and sends it back in both a JSON field and an
    /// HTML fragment. It runs no command, so no verdict may call it
    /// vulnerable — and `& echo <marker>` returning as `&amp; echo <marker>`
    /// is exactly the escaped-literal case (plan call 37).
    async fn patched_echo_handler(conn: ServerConn) {
        let mut ws = conn.ws().await;
        while let Some(Ok(message)) = ws.next().await {
            match message {
                Message::Text(text) => {
                    conn.record(text.as_bytes().to_vec());
                    let reply = match serde_json::from_str::<serde_json::Value>(&text)
                        .ok()
                        .and_then(|value| {
                            value.get("msg").and_then(|m| m.as_str()).map(seed_escape)
                        }) {
                        Some(escaped) => serde_json::json!({
                            "type": "echo",
                            "msg": escaped,
                            "html": format!("<b>{escaped}</b>"),
                        })
                        .to_string(),
                        None => r#"{"ok":true}"#.to_string(),
                    };
                    if ws.send(Message::text(reply)).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    }

    /// A transport whose connect always fails, standing in for a refused dial.
    struct DeadTransport;

    impl WsTransport for DeadTransport {
        fn connect<'a>(
            &'a self,
            _addr: std::net::SocketAddr,
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
        assert_eq!(meta.id, ID);
        assert_eq!(meta.id, "ws-cmdi-echo");
        assert_eq!(meta.name, "OS command injection echo via WebSocket");
        assert_eq!(meta.class, "cmdi");
        assert_eq!(meta.lanes, vec![LaneKind::Ws]);
        assert_eq!(
            meta.kinds,
            vec![
                InsertionKind::WsJsonValue,
                InsertionKind::WsText,
                InsertionKind::WsFormParam
            ]
        );
        assert_eq!(meta.intensity, Intensity::Medium);
        assert_eq!(meta.cost, CheckCost::Medium);
        assert_eq!(meta.technique, Technique::Reflected);
        assert_eq!(meta.confidence_max, Confidence::Firm);
        assert!(!meta.needs_baseline);
        assert_eq!(meta.wants_traits, None);
        assert!(!meta.targets_session);
        assert_eq!(meta.cwe, Some(78));
        assert_eq!(meta.origin, CheckOrigin::Native);
        assert!(meta.remediation.is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn vulnerable_server_runs_echo() {
        let (transport, log) = ws_server(None, shell_handler);
        let job = TestJob::new(100);
        let host = host_for(&job, transport as Arc<dyn WsTransport>);
        let marker = host.marker();
        let point = host.point().clone();

        let verdict = check().run(&point, &host as &dyn ProbeHost).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Vulnerable, Confidence::Firm)
        );
        assert!(
            verdict
                .detail
                .contains("echo of the marker without the literal payload"),
            "{}",
            verdict.detail
        );
        assert_eq!(verdict.evidence.payload, Some(format!(";echo {marker}")));
        assert_eq!(verdict.evidence.matched, Some(marker));
        assert_eq!(verdict.poc_hint, None);
        assert_eq!(
            log.connections(),
            1,
            "the first separator hits, so no further form is sent"
        );
        assert!(
            !format!("{verdict:?}").contains("s3cr3t-cookie"),
            "the fixture cookie never reaches a verdict: {verdict:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn echoing_the_literal_is_clean() {
        let (transport, log) = ws_server(None, echo_handler);
        let job = TestJob::new(100);
        let host = host_for(&job, transport as Arc<dyn WsTransport>);
        let point = host.point().clone();

        let verdict = check().run(&point, &host as &dyn ProbeHost).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Clean, Confidence::Tentative)
        );
        assert_eq!(verdict.evidence.payload, None);
        assert_eq!(verdict.evidence.matched, None);
        assert_eq!(
            log.connections(),
            5,
            "one dial per echo form, all five sent"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patched_escaping_echo_is_clean() {
        let (transport, log) = ws_server(None, patched_echo_handler);
        let job = TestJob::new(100);
        let host = host_for(&job, transport as Arc<dyn WsTransport>);
        let point = host.point().clone();

        let verdict = check().run(&point, &host as &dyn ProbeHost).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Clean, Confidence::Tentative),
            "an escaped echo is a reflection, not a command: {}",
            verdict.detail
        );
        assert_eq!(verdict.evidence.payload, None);
        assert_eq!(verdict.evidence.matched, None);
        assert_eq!(
            log.connections(),
            5,
            "one dial per echo form, all five sent"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn budget_zero_sends_nothing() {
        let (transport, log) = ws_server(None, shell_handler);
        let job = TestJob::new(0);
        let host = host_for(&job, transport as Arc<dyn WsTransport>);
        let point = host.point().clone();

        let verdict = check().run(&point, &host as &dyn ProbeHost).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Inconclusive, Confidence::Tentative)
        );
        assert_eq!(verdict.detail, "budget exhausted");
        assert_eq!(log.connections(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cancelled_job_sends_nothing() {
        let (transport, log) = ws_server(None, shell_handler);
        let job = TestJob::new(100);
        job.cancel();
        let host = host_for(&job, transport as Arc<dyn WsTransport>);
        let point = host.point().clone();

        let verdict = check().run(&point, &host as &dyn ProbeHost).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Inconclusive, Confidence::Tentative)
        );
        assert_eq!(verdict.detail, "cancelled");
        assert_eq!(log.connections(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn connect_error_is_inconclusive() {
        let job = TestJob::new(100);
        let host = host_for(&job, Arc::new(DeadTransport) as Arc<dyn WsTransport>);
        let point = host.point().clone();

        let verdict = check().run(&point, &host as &dyn ProbeHost).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Inconclusive, Confidence::Tentative)
        );
        assert!(
            verdict.detail.starts_with("connect error:"),
            "{}",
            verdict.detail
        );
    }
}
