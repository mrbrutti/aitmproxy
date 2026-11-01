//! `ws-subprotocol-observe`: how the target negotiates WebSocket subprotocols.
//!
//! Task 16 of the T4 plan, spec D8.3. The check is pure observation: it asks
//! for a subprotocol no server can have defined (`aitm-<job marker>`) and
//! records what the 101 says about it. Two answers are reported as issues at
//! `Info` (plan calls 6 and 33):
//!
//! - the server echoes the arbitrary token back, so it accepts *any*
//!   subprotocol a client names and its negotiation is decorative; and
//! - the server selects a subprotocol the client never offered, so the
//!   `Sec-WebSocket-Protocol` it sends is not the outcome of a negotiation.
//!
//! A server that refuses the upgrade is `Clean`, and so is one that completes
//! the 101 without selecting any subprotocol (call 33): RFC 6455 section 4.2.2
//! lets a server decline every offered subprotocol by omitting the header, and
//! it is the client's job to fail such a connection.
//!
//! The dialer records the 101's `Sec-WebSocket-Protocol` rather than enforcing
//! it (plan call 28), which is what makes both shapes observable at all: a
//! conforming client library fails the handshake on either.
//!
//! Nothing a server sends reaches the verdict: `Evidence.matched` is a scanner
//! constant and no detail carries a header value.

use std::sync::{Arc, OnceLock};

use aitm_scan_model::{
    Check, CheckCost, CheckMeta, CheckOrigin, Confidence, Evidence, InsertionKind, InsertionPoint,
    Intensity, LaneKind, Outcome, ProbeHost, ProbeResponse, RawProbe, Technique, Verdict,
};
use futures::future::BoxFuture;

use crate::checks::common;

/// The catalogue id of this check, also its `check.<id>` verb suffix.
pub const ID: &str = "ws-subprotocol-observe";

/// The handshake points this check has anything to say about (plan call 22).
///
/// Both name the negotiation: `origin` is the handshake point every captured
/// upgrade has, and `sec-websocket-protocol` exists exactly when the capture
/// asked for a subprotocol. The check is scheduled once per point, so it runs
/// at most twice per conversation and dials once each time.
const NEGOTIATION_POINTS: [&str; 2] = ["origin", "sec-websocket-protocol"];

/// The response header the whole check reads, lowercased as the dialer records
/// it.
const PROTOCOL_HEADER: &str = "sec-websocket-protocol";

/// `Evidence.matched` when the server handed our own token back.
const ECHOED: &str = "echoed Sec-WebSocket-Protocol";

/// The `ws-subprotocol-observe` check.
#[derive(Debug, Default, Clone, Copy)]
pub struct SubprotocolObserve;

/// This check, as the lane registers it.
#[must_use]
pub fn check() -> Arc<dyn Check> {
    Arc::new(SubprotocolObserve)
}

/// The catalogue entry, built once.
fn meta() -> &'static CheckMeta {
    static META: OnceLock<CheckMeta> = OnceLock::new();
    META.get_or_init(|| CheckMeta {
        id: ID.to_string(),
        name: "WebSocket subprotocol negotiation".to_string(),
        class: "ws-subprotocol".to_string(),
        lanes: vec![LaneKind::Ws],
        kinds: vec![InsertionKind::WsHandshakeHeader],
        intensity: Intensity::Light,
        cost: CheckCost::Light,
        technique: Technique::Observe,
        severity: aitm_poc::Severity::Info,
        confidence_max: Confidence::Firm,
        needs_baseline: false,
        wants_traits: None,
        targets_session: false,
        cwe: None,
        description: "Asks for an arbitrary subprotocol and records whether the server echoes it \
             back or completes the upgrade without selecting one."
            .to_string(),
        remediation: Some(
            "Accept only subprotocols the application implements, and refuse the upgrade when the \
             client offers none of them."
                .to_string(),
        ),
        origin: CheckOrigin::Native,
    })
}

impl Check for SubprotocolObserve {
    fn meta(&self) -> &CheckMeta {
        meta()
    }

    fn run<'a>(
        &'a self,
        point: &'a InsertionPoint,
        host: &'a dyn ProbeHost,
    ) -> BoxFuture<'a, Verdict> {
        Box::pin(async move {
            if !is_negotiation_point(point) {
                return common::clean("not a negotiation point", Evidence::default());
            }
            if let Some(reason) = common::stop_reason(host) {
                return common::inconclusive(reason, Vec::new());
            }

            let requested = format!("aitm-{}", host.marker());
            let response = match host
                .probe_raw(RawProbe {
                    method: "GET".to_string(),
                    url: String::new(),
                    headers: vec![("Sec-WebSocket-Protocol".to_string(), requested.clone())],
                    body: Vec::new(),
                })
                .await
            {
                Ok(response) => response,
                // The dialer's error text names the authority and the failure,
                // never a header (plan task 9-16 common shape).
                Err(err) => return common::connect_error(&err),
            };

            let evidence = Evidence {
                // A handshake check sends no payload string: what it changed is
                // a header, and a header value never reaches the evidence.
                payload: None,
                probe_flows: response.flow.into_iter().collect(),
                ..Evidence::default()
            };
            let Some(status) = response.status else {
                return common::inconclusive("the probe recorded no upgrade status", Vec::new());
            };
            if status != 101 {
                return common::clean(
                    format!("upgrade refused with status {status} for an arbitrary subprotocol"),
                    evidence,
                );
            }

            match selected(&response) {
                None => common::clean(
                    "upgrade completed without selecting a subprotocol; RFC 6455 lets a server \
                     decline every offered subprotocol, the client is expected to fail such a \
                     connection",
                    evidence,
                ),
                Some(protocol) if protocol == requested => vulnerable(
                    "server echoed an arbitrary subprotocol",
                    Evidence {
                        matched: Some(ECHOED.to_string()),
                        ..evidence
                    },
                ),
                // The probe offered exactly one token, so anything else the
                // server names was never on offer (call 33).
                Some(_) => vulnerable("server selected an unrequested subprotocol", evidence),
            }
        })
    }
}

/// Whether this point is one of the two the check acts on.
fn is_negotiation_point(point: &InsertionPoint) -> bool {
    NEGOTIATION_POINTS
        .iter()
        .any(|name| point.name.eq_ignore_ascii_case(name))
}

/// The subprotocol the 101 selected, if it selected one.
///
/// An empty value is read as "none selected" (call 33): a server that writes
/// the header with nothing in it has named no subprotocol either.
fn selected(response: &ProbeResponse) -> Option<&str> {
    response
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(PROTOCOL_HEADER))
        .map(|(_, value)| value.as_str())
        .filter(|value| !value.is_empty())
}

/// A `Vulnerable` verdict at this check's `confidence_max`; `poc_hint` is
/// always `None` for a WS check (plan call 19).
fn vulnerable(detail: impl Into<String>, evidence: Evidence) -> Verdict {
    Verdict {
        outcome: Outcome::Vulnerable,
        confidence: Confidence::Firm,
        evidence,
        detail: detail.into(),
        poc_hint: None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use aitm_core::{MemFlowStore, StdGuard};
    use aitm_scan_model::{
        CheckCost, CheckOrigin, Confidence, InsertionKind, Intensity, LaneKind, Outcome, Technique,
        Verdict,
    };
    use tokio_tungstenite::tungstenite::handshake::server::{create_response, ErrorResponse};
    use tokio_tungstenite::tungstenite::http::{HeaderValue, StatusCode};

    use super::{check, ID};
    use crate::testing::{
        echo_handler, point_and_host_for, ws_server, HandshakeDecision, ServerLog, TestJob,
    };
    use crate::transport::WsTransport;

    /// The subprotocol the check asks for, over a [`TestJob`]'s fixed marker.
    const REQUESTED: &str = "aitm-mk7f3a9e";

    /// Run the check against the fixture point `name`, over a server that
    /// answers every upgrade with `decide` and echoes every frame.
    async fn verdict_for(
        name: &str,
        decide: Option<HandshakeDecision>,
        job: &Arc<TestJob>,
    ) -> (Verdict, Arc<ServerLog>) {
        let (transport, log) = ws_server(decide, echo_handler);
        let (point, host) = point_and_host_for(name, job, transport as Arc<dyn WsTransport>);
        let verdict = check().run(&point, &host).await;
        (verdict, log)
    }

    /// A decision that completes the upgrade and echoes the requested
    /// subprotocol straight back — the seeded vulnerable target's behaviour.
    fn echo_the_subprotocol() -> HandshakeDecision {
        // The `Err` half is tungstenite's own `ErrorResponse`; the
        // `HandshakeDecision` contract fixes it, so it cannot be boxed away.
        #[allow(clippy::result_large_err)]
        let decide: HandshakeDecision = Arc::new(|request| {
            let mut response = create_response(request).expect("a 101 for the upgrade");
            if let Some(asked) = request.headers().get("sec-websocket-protocol") {
                response
                    .headers_mut()
                    .append("sec-websocket-protocol", asked.clone());
            }
            Ok(response)
        });
        decide
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn echoing_server_is_flagged() {
        let job = TestJob::new(100);

        let (verdict, log) =
            verdict_for("sec-websocket-protocol", Some(echo_the_subprotocol()), &job).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Vulnerable, Confidence::Firm)
        );
        assert!(
            verdict.detail.contains("echoed"),
            "detail must name the echo: {}",
            verdict.detail
        );
        assert_eq!(
            verdict.evidence.matched.as_deref(),
            Some("echoed Sec-WebSocket-Protocol")
        );
        assert_eq!(
            verdict.evidence.payload, None,
            "a handshake check sends no payload string"
        );
        assert!(
            log.handshakes()[0]
                .contains(&("sec-websocket-protocol".to_string(), REQUESTED.to_string())),
            "the check must ask for its own marker token: {:?}",
            log.handshakes()[0]
        );
        assert!(
            !format!("{verdict:?}").contains("s3cr3t-cookie"),
            "the verdict must not carry the replayed cookie: {verdict:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn server_completing_without_protocol_is_clean() {
        let job = TestJob::new(100);

        let (verdict, log) = verdict_for("sec-websocket-protocol", None, &job).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Clean, Confidence::Tentative)
        );
        assert!(
            verdict
                .detail
                .starts_with("upgrade completed without selecting a subprotocol"),
            "detail must say the server declined to select: {}",
            verdict.detail
        );
        assert_eq!(verdict.evidence.matched, None);
        assert_eq!(log.connections(), 1, "the observation still costs one dial");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patched_server_refuses_unknown_protocol() {
        // The `Err` half is tungstenite's own `ErrorResponse`; the
        // `HandshakeDecision` contract fixes it, so it cannot be boxed away.
        #[allow(clippy::result_large_err)]
        let decide: HandshakeDecision = Arc::new(|request| {
            let asked = request
                .headers()
                .get("sec-websocket-protocol")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            if asked == "chat" {
                return Ok(create_response(request).expect("a 101 for the upgrade"));
            }
            let mut refusal = ErrorResponse::new(Some("unsupported subprotocol".to_string()));
            *refusal.status_mut() = StatusCode::BAD_REQUEST;
            Err(refusal)
        });
        let job = TestJob::new(100);

        let (verdict, _log) = verdict_for("sec-websocket-protocol", Some(decide), &job).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Clean, Confidence::Tentative)
        );
        assert!(
            verdict.detail.contains("400"),
            "detail must carry the refusal status: {}",
            verdict.detail
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn server_selecting_an_unrequested_protocol_is_flagged() {
        // The `Err` half is tungstenite's own `ErrorResponse`; the
        // `HandshakeDecision` contract fixes it, so it cannot be boxed away.
        #[allow(clippy::result_large_err)]
        let decide: HandshakeDecision = Arc::new(|request| {
            let mut response = create_response(request).expect("a 101 for the upgrade");
            response
                .headers_mut()
                .append("sec-websocket-protocol", HeaderValue::from_static("chat"));
            Ok(response)
        });
        let job = TestJob::new(100);

        let (verdict, _log) = verdict_for("sec-websocket-protocol", Some(decide), &job).await;

        // The probe offered only `aitm-<marker>`; `chat` was never on offer.
        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Vulnerable, Confidence::Firm)
        );
        assert_eq!(verdict.detail, "server selected an unrequested subprotocol");
        assert_eq!(verdict.evidence.matched, None);
        assert!(
            !format!("{verdict:?}").contains("s3cr3t-cookie"),
            "the verdict must not carry the replayed cookie: {verdict:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_origin_point_is_a_negotiation_point_too() {
        let job = TestJob::new(100);

        let (verdict, log) = verdict_for("origin", Some(echo_the_subprotocol()), &job).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Vulnerable, Confidence::Firm)
        );
        assert_eq!(log.connections(), 1, "the origin point is probed once");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_frame_point_is_clean_with_a_reason() {
        let job = TestJob::new(100);

        let (verdict, log) = verdict_for("msg", Some(echo_the_subprotocol()), &job).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Clean, Confidence::Tentative)
        );
        assert_eq!(verdict.detail, "not a negotiation point");
        assert_eq!(log.connections(), 0, "a frame point is never dialled");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn budget_zero_is_inconclusive() {
        let job = TestJob::new(0);

        let (verdict, log) = verdict_for("sec-websocket-protocol", None, &job).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Inconclusive, Confidence::Tentative)
        );
        assert_eq!(verdict.detail, "budget exhausted");
        assert_eq!(log.connections(), 0, "no socket is opened without budget");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cancelled_is_inconclusive() {
        let job = TestJob::new(100);
        job.cancel();

        let (verdict, log) = verdict_for("sec-websocket-protocol", None, &job).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Inconclusive, Confidence::Tentative)
        );
        assert_eq!(verdict.detail, "cancelled");
        assert_eq!(log.connections(), 0, "a cancelled job opens no socket");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_refused_dial_is_inconclusive() {
        // An empty scope: the guard refuses the authority before any socket.
        let job = TestJob::over(
            Arc::new(MemFlowStore::new()),
            Arc::new(StdGuard::default()),
            100,
            |_| {},
        );

        let (verdict, log) = verdict_for("sec-websocket-protocol", None, &job).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Inconclusive, Confidence::Tentative)
        );
        assert!(
            verdict.detail.starts_with("connect error: "),
            "detail must name the connect error: {}",
            verdict.detail
        );
        assert_eq!(
            log.connections(),
            0,
            "an out-of-scope authority is not dialled"
        );
    }

    #[test]
    fn meta_is_the_catalogue_entry() {
        let meta = check().meta().clone();

        assert_eq!(meta.id, ID);
        assert_eq!(meta.id, "ws-subprotocol-observe");
        assert_eq!(meta.name, "WebSocket subprotocol negotiation");
        assert_eq!(meta.class, "ws-subprotocol");
        assert_eq!(meta.lanes, vec![LaneKind::Ws]);
        assert_eq!(meta.kinds, vec![InsertionKind::WsHandshakeHeader]);
        assert_eq!(meta.intensity, Intensity::Light);
        assert_eq!(meta.cost, CheckCost::Light);
        assert_eq!(meta.technique, Technique::Observe);
        assert_eq!(meta.severity, aitm_poc::Severity::Info);
        assert_eq!(meta.confidence_max, Confidence::Firm);
        assert!(!meta.needs_baseline);
        assert_eq!(meta.wants_traits, None);
        assert!(!meta.targets_session);
        assert_eq!(meta.cwe, None);
        assert_eq!(meta.origin, CheckOrigin::Native);
        assert!(!meta.description.is_empty());
        assert!(meta.remediation.is_some());
    }
}
