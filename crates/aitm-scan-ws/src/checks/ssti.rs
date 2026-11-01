//! The `ws-ssti` check — written by task 13 of the T4 plan.
//!
//! Server-side template injection through a WebSocket message field (spec
//! D8.3 "Checks"): the check places an arithmetic canary — this scan's marker
//! immediately followed by `1543*7` in one of four template syntaxes — at the
//! insertion point and looks for the *product* next to the marker in the
//! reply. A server that echoes the template source unchanged has reflected
//! input, not evaluated it, so [`payloads::ssti_hit`](crate::payloads::ssti_hit)
//! requires the expectation to be present **and** the literal payload to be
//! absent.
//!
//! The canary is inert: it renders a number. It reads nothing, writes nothing
//! and runs nothing on the target beyond the arithmetic a template engine does
//! for any expression, which is what keeps this safe to schedule against an
//! authorised target. Carrying the marker through both the payload and the
//! expectation is what stops a page that prints `10801` of its own accord from
//! firing.
//!
//! Evidence never carries server text: `matched` is the marker-bearing
//! expectation this crate built and `payload` is the canary it sent, so no
//! captured cookie, header or reply body can leave the check in a verdict.

use std::sync::{Arc, OnceLock};

use aitm_scan_model::{
    Check, CheckCost, CheckMeta, CheckOrigin, Confidence, Evidence, FlowRef, InsertionKind,
    InsertionPoint, Intensity, LaneKind, Outcome, Payload, PayloadMode, ProbeHost, Technique,
    Verdict,
};
use futures::future::BoxFuture;

use crate::checks::common;

use crate::payloads::{ssti_hit, ssti_probes, SSTI_A, SSTI_B};

/// The catalogue id of this check, also the `check.<id>` verb's suffix.
pub const ID: &str = "ws-ssti";

/// Server-side template injection in a WebSocket message field.
///
/// Stateless: one instance serves every point of every job, as
/// [`crate::checks::all`] registers it.
pub struct Ssti;

/// The `ws-ssti` check, ready for the lane's registry.
#[must_use]
pub fn check() -> Arc<dyn Check> {
    Arc::new(Ssti)
}

/// The catalogue entry, built once.
fn catalogue_entry() -> &'static CheckMeta {
    static META: OnceLock<CheckMeta> = OnceLock::new();
    META.get_or_init(|| CheckMeta {
        id: ID.to_string(),
        name: "Server-side template injection via WebSocket".to_string(),
        class: "ssti".to_string(),
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
        confidence_max: Confidence::Certain,
        needs_baseline: false,
        wants_traits: None,
        targets_session: false,
        cwe: Some(1336),
        description: format!(
            "Sends an arithmetic template canary ({SSTI_A}*{SSTI_B}) in four template \
             syntaxes and reports the field as template-injectable when the server renders \
             the product next to this scan's marker."
        ),
        remediation: Some(
            "Never render client-supplied text as a template; pass it to a fixed template as \
             data, and sandbox the engine so expressions in data are not evaluated."
                .to_string(),
        ),
        origin: CheckOrigin::Native,
    })
}

impl Check for Ssti {
    fn meta(&self) -> &CheckMeta {
        catalogue_entry()
    }

    /// One probe per template, stopping at the first evaluated one.
    fn run<'a>(
        &'a self,
        _point: &'a InsertionPoint,
        host: &'a dyn ProbeHost,
    ) -> BoxFuture<'a, Verdict> {
        Box::pin(probe_each_template(host))
    }
}

/// Try each template in turn; the first evaluated one is the verdict.
async fn probe_each_template(host: &dyn ProbeHost) -> Verdict {
    let probes = ssti_probes(&host.marker());
    let mut probe_flows: Vec<FlowRef> = Vec::new();

    for (payload, expected) in &probes {
        if let Some(reason) = common::stop_reason(host) {
            return common::inconclusive(reason, probe_flows);
        }
        let sent = Payload {
            value: payload.clone(),
            mode: PayloadMode::Replace,
            bytes: None,
        };
        let response = match host.probe(&sent).await {
            Ok(response) => response,
            // The dialer's error text names the host and the failure, never a
            // header: a connect failure is "could not tell", not "clean".
            Err(error) => {
                let mut verdict = common::connect_error(&error);
                verdict.evidence.probe_flows = probe_flows;
                return verdict;
            }
        };
        probe_flows.extend(response.flow);
        if ssti_hit(&String::from_utf8_lossy(&response.body), payload, expected) {
            return Verdict {
                outcome: Outcome::Vulnerable,
                confidence: Confidence::Certain,
                evidence: Evidence {
                    payload: Some(payload.clone()),
                    matched: Some(expected.clone()),
                    probe_flows,
                    ..Evidence::default()
                },
                detail: format!(
                    "template expression evaluated: {SSTI_A}*{SSTI_B} rendered next to the marker"
                ),
                poc_hint: None,
            };
        }
    }

    Verdict {
        outcome: Outcome::Clean,
        confidence: Confidence::Tentative,
        evidence: Evidence {
            probe_flows,
            ..Evidence::default()
        },
        detail: format!(
            "no template expression evaluated after {} template syntaxes",
            probes.len()
        ),
        poc_hint: None,
    }
}

#[cfg(test)]
mod tests {
    use aitm_scan_model::{
        CheckCost, CheckOrigin, Confidence, InsertionKind, Intensity, LaneKind, Outcome, Technique,
    };
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    use super::{check, ID};
    use crate::testing::{echo_handler, host_for, ws_server, ServerConn, TestJob};

    /// The first payload `payloads::ssti_probes` builds for the fixture marker.
    const MUSTACHE: &str = "mk7f3a9e{{1543*7}}";

    /// What every SSTI probe looks for in a reply, for that marker.
    const EXPECTED: &str = "mk7f3a9e10801";

    /// The seeded vulnerable target: a template engine renders the field.
    ///
    /// Whatever the client sends is echoed with `{{1543*7}}` replaced by its
    /// product, exactly as a server that evaluates the field as a template
    /// would answer — the marker the canary carries stays where it was, so the
    /// product comes back next to it.
    async fn renders_mustache(conn: ServerConn) {
        let mut ws = conn.ws().await;
        while let Some(Ok(message)) = ws.next().await {
            match message {
                Message::Text(text) => {
                    conn.record(text.as_bytes().to_vec());
                    let rendered = text.as_str().replace("{{1543*7}}", "10801");
                    if ws.send(Message::text(rendered)).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    }

    /// A server that answers every text frame with `reply`, ignoring the input.
    async fn constant(conn: ServerConn, reply: &str) {
        let mut ws = conn.ws().await;
        while let Some(Ok(message)) = ws.next().await {
            match message {
                Message::Text(text) => {
                    conn.record(text.as_bytes().to_vec());
                    if ws.send(Message::text(reply.to_string())).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    }

    /// A server whose replies always carry a bare `49`.
    async fn always_49(conn: ServerConn) {
        constant(conn, "49").await;
    }

    /// A server whose replies always carry the bare product, with no marker.
    async fn always_product(conn: ServerConn) {
        constant(conn, "the total is 10801").await;
    }

    #[test]
    fn meta_is_the_catalogue_entry() {
        let meta = check().meta().clone();

        assert_eq!(meta.id, ID);
        assert_eq!(meta.id, "ws-ssti");
        assert_eq!(meta.name, "Server-side template injection via WebSocket");
        assert_eq!(meta.class, "ssti");
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
        assert_eq!(meta.severity, aitm_poc::Severity::High);
        assert_eq!(meta.confidence_max, Confidence::Certain);
        assert!(!meta.needs_baseline);
        assert_eq!(meta.wants_traits, None);
        assert!(!meta.targets_session);
        assert_eq!(meta.cwe, Some(1336));
        assert_eq!(meta.origin, CheckOrigin::Native);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn vulnerable_server_evaluates_mustache() {
        let (transport, log) = ws_server(None, renders_mustache);
        let job = TestJob::new(100);
        let host = host_for("msg", &job, transport);
        let ssti = check();

        let verdict = ssti.run(host.point(), &host).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Vulnerable, Confidence::Certain)
        );
        assert_eq!(verdict.evidence.matched.as_deref(), Some(EXPECTED));
        assert_eq!(verdict.evidence.payload.as_deref(), Some(MUSTACHE));
        assert!(
            verdict.detail.contains("template expression evaluated"),
            "{}",
            verdict.detail
        );
        assert_eq!(
            log.connections(),
            1,
            "the first template hits, so the other three are never sent"
        );
        assert!(
            !format!("{verdict:?}").contains("s3cr3t-cookie"),
            "no captured credential reaches a verdict: {verdict:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patched_echo_is_clean() {
        let (transport, log) = ws_server(None, echo_handler);
        let job = TestJob::new(100);
        let host = host_for("msg", &job, transport);
        let ssti = check();

        let verdict = ssti.run(host.point(), &host).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Clean, Confidence::Tentative)
        );
        assert!(
            verdict.detail.contains("no template expression evaluated"),
            "{}",
            verdict.detail
        );
        assert_eq!(
            log.connections(),
            4,
            "one dial per template, all four tried"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bare_49_never_fires() {
        let (transport, _log) = ws_server(None, always_49);
        let job = TestJob::new(100);
        let host = host_for("msg", &job, transport);
        let ssti = check();

        let verdict = ssti.run(host.point(), &host).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Clean, Confidence::Tentative)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_product_without_the_marker_never_fires() {
        let (transport, _log) = ws_server(None, always_product);
        let job = TestJob::new(100);
        let host = host_for("msg", &job, transport);
        let ssti = check();

        let verdict = ssti.run(host.point(), &host).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Clean, Confidence::Tentative),
            "a page that prints 10801 of its own accord is not an evaluation: \
             the product has to be rendered next to this scan's marker"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cancelled_job_is_inconclusive_before_any_connect() {
        let (transport, log) = ws_server(None, echo_handler);
        let job = TestJob::new(100);
        job.cancel();
        let host = host_for("msg", &job, transport);
        let ssti = check();

        let verdict = ssti.run(host.point(), &host).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Inconclusive, Confidence::Tentative)
        );
        assert_eq!(verdict.detail, "cancelled");
        assert_eq!(log.connections(), 0);
    }
}
