//! The `ws-auth-bypass-handshake` check — written by task 10 of the T4 plan.
//!
//! Spec D8.3: "dial with `Cookie`/`Authorization` stripped: still 101 and
//! authenticated-looking data -> `high`/`firm`". The check re-dials the captured
//! upgrade with both session headers stripped (`probe_raw`, whose header list is
//! a set of overrides and whose empty value strips) and compares the first
//! server data frame with the authenticated baseline's. An identical first reply
//! means the server served the same authenticated conversation to a request that
//! carried no credentials.
//!
//! It acts on the `cookie` and `authorization` handshake points only (plan call
//! 22): those points exist exactly when the captured handshake carried the
//! header, so the spec's "skipped when the handshake carried neither" is "never
//! scheduled" and any other point gets a `Clean` verdict naming the reason.
//!
//! Redaction: the probed header values are never read by this check and never
//! reach a verdict. The only text that leaves the module is the fixed
//! `MATCHED_IDENTICAL` constant and, for a differing reply, a server frame
//! excerpt that goes through `aitm_core::redact::scrub_text` before
//! `Evidence::excerpt` bounds it.

use std::sync::{Arc, OnceLock};
use std::time::Instant;

use aitm_core::redact::scrub_text;
use aitm_scan_model::{
    Check, CheckCost, CheckMeta, CheckOrigin, Confidence, Evidence, Frame, FrameKind,
    InsertionKind, InsertionPoint, Intensity, LaneKind, Outcome, ProbeHost, ProbeResponse,
    RawProbe, Technique, Verdict,
};
use futures::future::BoxFuture;

/// The check's catalogue identifier, also its `check.<id>` verb suffix.
pub const ID: &str = "ws-auth-bypass-handshake";

/// What `Evidence.matched` carries for a confirmed bypass: a scanner constant,
/// never the server's text, so no authenticated payload leaves the process.
const MATCHED_IDENTICAL: &str = "first server frame identical to baseline";

/// Detects a WebSocket upgrade that serves authenticated data with the session
/// headers stripped (spec D8.3, CWE-287).
pub struct WsAuthBypassHandshake;

/// The `ws-auth-bypass-handshake` check, ready for the lane's catalogue.
#[must_use]
pub fn check() -> Arc<dyn Check> {
    Arc::new(WsAuthBypassHandshake)
}

/// The fixed catalogue entry, built once (plan "Tasks 9-16", call 6).
fn meta() -> &'static CheckMeta {
    static META: OnceLock<CheckMeta> = OnceLock::new();
    META.get_or_init(|| CheckMeta {
        id: ID.to_string(),
        name: "WebSocket upgrade without credentials".to_string(),
        class: "ws-auth-bypass".to_string(),
        lanes: vec![LaneKind::Ws],
        kinds: vec![InsertionKind::WsHandshakeHeader],
        intensity: Intensity::Light,
        cost: CheckCost::Light,
        technique: Technique::Handshake,
        severity: aitm_poc::Severity::High,
        confidence_max: Confidence::Firm,
        needs_baseline: true,
        wants_traits: None,
        targets_session: false,
        cwe: Some(287),
        description: "Re-sends the captured WebSocket upgrade with the Cookie and Authorization \
                      headers stripped and reports a server that still completes the upgrade and \
                      replies with the authenticated baseline's first frame."
            .to_string(),
        remediation: Some(
            "Authenticate the upgrade request itself and refuse it with 401 or 403 when the \
             session credentials are absent or invalid, rather than authenticating later frames."
                .to_string(),
        ),
        origin: CheckOrigin::Native,
    })
}

/// The stripping probe: both session headers overridden to empty, which the WS
/// probe host reads as "strip". Method and body are ignored by the host (an
/// upgrade is a bodyless GET) and the URL stays the captured authority's.
fn stripped_credentials() -> RawProbe {
    RawProbe {
        method: "GET".to_string(),
        url: String::new(),
        headers: vec![
            ("Cookie".to_string(), String::new()),
            ("Authorization".to_string(), String::new()),
        ],
        body: Vec::new(),
    }
}

/// The first Text or Binary frame of a reply; control frames are not the oracle.
fn first_data_frame(response: &ProbeResponse) -> Option<&Frame> {
    response
        .ws_frames
        .as_ref()?
        .iter()
        .find(|frame| matches!(frame.kind, FrameKind::Text | FrameKind::Binary))
}

/// Two replies are "the same reply" when the opcode and the bytes both match.
fn same_reply(probe: &Frame, baseline: &Frame) -> bool {
    probe.kind == baseline.kind && probe.payload == baseline.payload
}

/// A verdict with no evidence, for the outcomes reached before any probe.
fn bare(outcome: Outcome, detail: impl Into<String>) -> Verdict {
    Verdict {
        outcome,
        confidence: Confidence::Tentative,
        evidence: Evidence::default(),
        detail: detail.into(),
        poc_hint: None,
    }
}

impl Check for WsAuthBypassHandshake {
    fn meta(&self) -> &CheckMeta {
        meta()
    }

    fn run<'a>(
        &'a self,
        point: &'a InsertionPoint,
        host: &'a dyn ProbeHost,
    ) -> BoxFuture<'a, Verdict> {
        Box::pin(async move {
            if !matches!(point.name.as_str(), "cookie" | "authorization") {
                return bare(
                    Outcome::Clean,
                    "acts on the cookie/authorization handshake points",
                );
            }
            if let Some(stop) = stop_reason(host) {
                return bare(Outcome::Inconclusive, stop);
            }

            let baseline = match host.baseline().await {
                Ok(response) => response,
                Err(error) => {
                    return bare(Outcome::Inconclusive, format!("connect error: {error}"))
                }
            };
            if let Some(stop) = stop_reason(host) {
                return bare(Outcome::Inconclusive, stop);
            }
            let probe = match host.probe_raw(stripped_credentials()).await {
                Ok(response) => response,
                Err(error) => {
                    return bare(Outcome::Inconclusive, format!("connect error: {error}"))
                }
            };

            let evidence = Evidence {
                payload: None,
                matched: None,
                probe_flows: probe.flow.into_iter().collect(),
                baseline_flow: baseline.flow,
                ..Evidence::default()
            };

            match probe.status {
                Some(101) => match (first_data_frame(&probe), first_data_frame(&baseline)) {
                    (Some(reply), Some(authenticated)) if same_reply(reply, authenticated) => {
                        Verdict {
                            outcome: Outcome::Vulnerable,
                            confidence: Confidence::Firm,
                            evidence: Evidence {
                                matched: Some(MATCHED_IDENTICAL.to_string()),
                                ..evidence
                            },
                            detail: "upgrade completed without Cookie/Authorization and the first \
                                     reply equals the authenticated baseline"
                                .to_string(),
                            poc_hint: None,
                        }
                    }
                    (reply, _) => Verdict {
                        outcome: Outcome::Clean,
                        confidence: Confidence::Tentative,
                        evidence: Evidence {
                            matched: reply.map(|frame| {
                                Evidence::excerpt(&scrub_text(&String::from_utf8_lossy(
                                    &frame.payload,
                                )))
                            }),
                            ..evidence
                        },
                        detail: "reply differs or absent without credentials".to_string(),
                        poc_hint: None,
                    },
                },
                Some(status) => Verdict {
                    outcome: Outcome::Clean,
                    confidence: Confidence::Tentative,
                    evidence,
                    detail: format!("upgrade refused with status {status} without credentials"),
                    poc_hint: None,
                },
                None => Verdict {
                    outcome: Outcome::Inconclusive,
                    confidence: Confidence::Tentative,
                    evidence,
                    detail: "the upgrade produced no handshake status".to_string(),
                    poc_hint: None,
                },
            }
        })
    }
}

/// Why the check must send nothing more, when it must: the three stop
/// conditions every check polls between probes.
fn stop_reason(host: &dyn ProbeHost) -> Option<&'static str> {
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use aitm_scan_model::{
        CheckCost, CheckOrigin, Confidence, InsertionKind, Intensity, JobCtx, LaneKind, Outcome,
        Technique,
    };
    use futures::SinkExt;
    use tokio_tungstenite::tungstenite::handshake::server::{
        create_response, ErrorResponse, Request,
    };
    use tokio_tungstenite::tungstenite::http::StatusCode;
    use tokio_tungstenite::tungstenite::Message;

    use super::{check, ID};
    use crate::dialer::WsDialer;
    use crate::discover::{discover_flow, IdGen};
    use crate::host::WsProbeHost;
    use crate::testing::{
        captured_conversation, echo_handler, ws_server, DuplexTransport, HandshakeDecision,
        ServerConn, ServerLog, TestJob,
    };
    use crate::transport::WsTransport;

    /// The seeded target's authenticated greeting, sent right after the upgrade.
    const ALICE: &str = r#"{"type":"hello","user":"alice"}"#;

    /// The same greeting for a connection that carried no session.
    const ANONYMOUS: &str = r#"{"type":"hello","user":"anonymous"}"#;

    /// A host over the fixture conversation's point named `name`.
    fn host_for(name: &str, job: &Arc<TestJob>, transport: Arc<DuplexTransport>) -> WsProbeHost {
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
            Arc::new(WsDialer::new(transport as Arc<dyn WsTransport>)),
            Arc::clone(job) as Arc<dyn JobCtx>,
        )
        .expect("the fixture point builds a host")
    }

    /// The value of one (lowercase) header of the server's `nth` handshake.
    fn handshake_header(log: &ServerLog, nth: usize, name: &str) -> Option<String> {
        log.handshakes().get(nth).and_then(|headers| {
            headers
                .iter()
                .find(|(header, _)| header == name)
                .map(|(_, value)| value.clone())
        })
    }

    /// The patched seeded target: the greeting names the cookie's user, and an
    /// unauthenticated connection is greeted as `anonymous`.
    async fn hello_by_cookie(conn: ServerConn) {
        let greeting = if conn.header("cookie").is_some() {
            ALICE
        } else {
            ANONYMOUS
        };
        let mut ws = conn.ws().await;
        let _ = ws.send(Message::text(greeting)).await;
    }

    /// The vulnerable seeded target: authenticated data with or without a cookie.
    async fn hello_always_alice(conn: ServerConn) {
        let mut ws = conn.ws().await;
        let _ = ws.send(Message::text(ALICE)).await;
    }

    /// Echoes for an authenticated connection, refuses in-band without one.
    async fn echo_or_unauthenticated(conn: ServerConn) {
        if conn.header("cookie").is_some() {
            echo_handler(conn).await;
            return;
        }
        let mut ws = conn.ws().await;
        let _ = ws
            .send(Message::text(r#"{"error":"unauthenticated"}"#))
            .await;
    }

    /// A `HandshakeDecision` that answers 401 when the upgrade carries no cookie.
    fn cookie_required() -> HandshakeDecision {
        // The `Err` half is tungstenite's own `ErrorResponse`; the
        // `HandshakeDecision` contract fixes it, so it cannot be boxed away.
        #[allow(clippy::result_large_err)]
        Arc::new(|request: &Request| {
            if request.headers().contains_key("cookie") {
                return Ok(create_response(request).expect("a 101 base response"));
            }
            let mut refusal = ErrorResponse::new(Some("unauthorized".to_string()));
            *refusal.status_mut() = StatusCode::UNAUTHORIZED;
            Err(refusal)
        })
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn vulnerable_server_ignores_cookie() {
        let (transport, log) = ws_server(None, echo_handler);
        let job = TestJob::new(100);
        let host = host_for("cookie", &job, transport);
        let check = check();

        let verdict = check.run(host.point(), &host).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Vulnerable, Confidence::Firm),
            "{}",
            verdict.detail
        );
        assert!(
            verdict
                .detail
                .contains("upgrade completed without Cookie/Authorization"),
            "{}",
            verdict.detail
        );
        assert_eq!(
            verdict.evidence.matched.as_deref(),
            Some("first server frame identical to baseline")
        );
        assert_eq!(
            verdict.evidence.payload, None,
            "a handshake check sends no payload"
        );
        assert_eq!(verdict.poc_hint, None, "no ws PoC step exists in v2");
        assert_eq!(
            handshake_header(&log, 0, "cookie").as_deref(),
            Some("sid=s3cr3t-cookie"),
            "the baseline keeps the captured session"
        );
        assert_eq!(
            handshake_header(&log, 1, "cookie"),
            None,
            "the probe strips the cookie"
        );
        assert_eq!(
            handshake_header(&log, 1, "authorization"),
            None,
            "and the authorization header with it"
        );
        assert!(
            !format!("{verdict:?}").contains("s3cr3t-cookie"),
            "no header value reaches the verdict: {verdict:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn seeded_vulnerable_target_greets_alice_without_the_cookie() {
        let (transport, log) = ws_server(None, hello_always_alice);
        let job = TestJob::new(100);
        let host = host_for("cookie", &job, transport);
        let check = check();

        let verdict = check.run(host.point(), &host).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Vulnerable, Confidence::Firm),
            "{}",
            verdict.detail
        );
        assert!(
            verdict
                .detail
                .contains("the first reply equals the authenticated baseline"),
            "{}",
            verdict.detail
        );
        assert_eq!(log.connections(), 2, "the baseline and one stripped probe");
        assert!(
            !format!("{verdict:?}").contains("s3cr3t-cookie"),
            "no header value reaches the verdict: {verdict:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patched_server_requires_cookie() {
        let (transport, log) = ws_server(Some(cookie_required()), echo_handler);
        let job = TestJob::new(100);
        let host = host_for("cookie", &job, transport);
        let check = check();

        let verdict = check.run(host.point(), &host).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Clean, Confidence::Tentative),
            "{}",
            verdict.detail
        );
        assert!(verdict.detail.contains("401"), "{}", verdict.detail);
        assert_eq!(
            log.connections(),
            1,
            "only the baseline completed an upgrade"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn different_reply_is_clean() {
        let (transport, _log) = ws_server(None, echo_or_unauthenticated);
        let job = TestJob::new(100);
        let host = host_for("cookie", &job, transport);
        let check = check();

        let verdict = check.run(host.point(), &host).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Clean, Confidence::Tentative),
            "{}",
            verdict.detail
        );
        assert!(verdict.detail.contains("differs"), "{}", verdict.detail);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn seeded_patched_target_greets_anonymous() {
        let (transport, _log) = ws_server(None, hello_by_cookie);
        let job = TestJob::new(100);
        let host = host_for("cookie", &job, transport);
        let check = check();

        let verdict = check.run(host.point(), &host).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Clean, Confidence::Tentative),
            "{}",
            verdict.detail
        );
        assert!(verdict.detail.contains("differs"), "{}", verdict.detail);
        assert!(
            !format!("{verdict:?}").contains("s3cr3t-cookie"),
            "no header value reaches the verdict: {verdict:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn origin_point_is_clean_with_reason() {
        let (transport, log) = ws_server(None, echo_handler);
        let job = TestJob::new(100);
        let host = host_for("origin", &job, transport);
        let check = check();

        let verdict = check.run(host.point(), &host).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Clean, Confidence::Tentative),
            "{}",
            verdict.detail
        );
        assert!(
            verdict.detail.contains("cookie/authorization"),
            "{}",
            verdict.detail
        );
        assert_eq!(log.connections(), 0, "a point this check skips never dials");
        assert_eq!(job.charged(), 0, "and costs no budget");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cancelled_job_sends_nothing() {
        let (transport, log) = ws_server(None, echo_handler);
        let job = TestJob::new(100);
        let host = host_for("cookie", &job, transport);
        job.cancel();
        let check = check();

        let verdict = check.run(host.point(), &host).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Inconclusive, Confidence::Tentative)
        );
        assert_eq!(verdict.detail, "cancelled");
        assert_eq!(log.connections(), 0, "a cancelled job never dials");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn exhausted_budget_sends_nothing() {
        let (transport, log) = ws_server(None, echo_handler);
        let job = TestJob::new(0);
        let host = host_for("cookie", &job, transport);
        let check = check();

        let verdict = check.run(host.point(), &host).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Inconclusive, Confidence::Tentative)
        );
        assert_eq!(verdict.detail, "budget exhausted");
        assert_eq!(log.connections(), 0, "an exhausted job never dials");
    }

    #[test]
    fn meta_is_the_fixed_catalogue_entry() {
        let check = check();
        let meta = check.meta();

        assert_eq!(meta.id, ID);
        assert_eq!(meta.id, "ws-auth-bypass-handshake");
        assert_eq!(meta.name, "WebSocket upgrade without credentials");
        assert_eq!(meta.class, "ws-auth-bypass");
        assert_eq!(meta.lanes, vec![LaneKind::Ws]);
        assert_eq!(meta.kinds, vec![InsertionKind::WsHandshakeHeader]);
        assert_eq!(meta.intensity, Intensity::Light);
        assert_eq!(meta.cost, CheckCost::Light);
        assert_eq!(meta.technique, Technique::Handshake);
        assert_eq!(meta.severity, aitm_poc::Severity::High);
        assert_eq!(meta.confidence_max, Confidence::Firm);
        assert!(meta.needs_baseline);
        assert_eq!(meta.wants_traits, None);
        assert!(!meta.targets_session);
        assert_eq!(meta.cwe, Some(287));
        assert_eq!(meta.origin, CheckOrigin::Native);
        assert!(meta.remediation.is_some());
    }
}
