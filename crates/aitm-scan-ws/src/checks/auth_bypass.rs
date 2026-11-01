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

use aitm_core::redact::scrub_text;
use aitm_scan_model::{
    Check, CheckCost, CheckMeta, CheckOrigin, Confidence, Evidence, Frame, InsertionKind,
    InsertionPoint, Intensity, LaneKind, Outcome, ProbeHost, RawProbe, Technique, Verdict,
};
use futures::future::BoxFuture;

use crate::checks::common;

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

/// Two replies are "the same reply" when the opcode and the bytes both match.
fn same_reply(probe: &Frame, baseline: &Frame) -> bool {
    probe.kind == baseline.kind && probe.payload == baseline.payload
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
                return common::clean(
                    "acts on the cookie/authorization handshake points",
                    Evidence::default(),
                );
            }
            if let Some(stop) = common::stop_reason(host) {
                return common::inconclusive(stop, Vec::new());
            }

            let baseline = match host.baseline().await {
                Ok(response) => response,
                Err(error) => return common::connect_error(&error, Vec::new()),
            };
            if let Some(stop) = common::stop_reason(host) {
                return common::inconclusive(stop, Vec::new());
            }
            let probe = match host.probe_raw(stripped_credentials()).await {
                Ok(response) => response,
                // The probe never connected, so it has no flow of its own; the
                // baseline's flow is the baseline's, and goes in the field that
                // says so — as every other check's connect error does.
                Err(error) => {
                    return Verdict {
                        evidence: Evidence {
                            baseline_flow: baseline.flow,
                            ..Evidence::default()
                        },
                        ..common::connect_error(&error, Vec::new())
                    }
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
                Some(101) => match (
                    common::first_data_frame(&probe),
                    common::first_data_frame(&baseline),
                ) {
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use aitm_core::ByteStream;
    use aitm_scan_model::{
        CheckCost, CheckOrigin, Confidence, InsertionKind, Intensity, LaneKind, Outcome,
        RecordProbes, Technique,
    };
    use futures::future::BoxFuture;
    use futures::SinkExt;
    use tokio_tungstenite::tungstenite::handshake::server::{
        create_response, ErrorResponse, Request,
    };
    use tokio_tungstenite::tungstenite::http::StatusCode;
    use tokio_tungstenite::tungstenite::Message;

    use super::{check, ID};
    use crate::testing::{
        echo_handler, handshake_header, host_for, ws_server, DuplexTransport, HandshakeDecision,
        ServerConn, TestJob,
    };
    use crate::transport::WsTransport;

    /// The seeded target's authenticated greeting, sent right after the upgrade.
    const ALICE: &str = r#"{"type":"hello","user":"alice"}"#;

    /// The same greeting for a connection that carried no session.
    const ANONYMOUS: &str = r#"{"type":"hello","user":"anonymous"}"#;

    /// The value of one (lowercase) header of the server's `nth` handshake.
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

    /// A transport whose first connect succeeds and whose later ones refuse,
    /// so a check takes its baseline and then loses the target.
    struct RefuseAfterFirst {
        inner: Arc<DuplexTransport>,
        seen: AtomicUsize,
    }

    impl WsTransport for RefuseAfterFirst {
        fn connect<'a>(
            &'a self,
            addr: std::net::SocketAddr,
            tls: bool,
            sni: &'a str,
        ) -> BoxFuture<'a, anyhow::Result<ByteStream>> {
            if self.seen.fetch_add(1, Ordering::SeqCst) == 0 {
                return self.inner.connect(addr, tls, sni);
            }
            Box::pin(async { Err(anyhow::anyhow!("connection refused")) })
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_probe_that_never_connected_has_no_probe_flow() {
        // The baseline's flow used to be handed to `connect_error` as the
        // probe's, so evidence claimed a probe flow for a probe that never
        // opened a socket. It belongs in `baseline_flow`, where every other
        // check's connect error puts it.
        let (inner, _log) = ws_server(None, echo_handler);
        let transport = Arc::new(RefuseAfterFirst {
            inner,
            seen: AtomicUsize::new(0),
        });
        let job = TestJob::with(100, |profile| {
            profile.http.record_probes = RecordProbes::All;
        });
        let host = host_for("cookie", &job, transport);

        let verdict = check().run(host.point(), &host).await;

        assert_eq!(verdict.outcome, Outcome::Inconclusive, "{}", verdict.detail);
        assert!(
            verdict.detail.starts_with("connect error: "),
            "{}",
            verdict.detail
        );
        assert_eq!(
            verdict.evidence.probe_flows,
            Vec::new(),
            "a probe that never connected has no flow of its own"
        );
        assert!(
            verdict.evidence.baseline_flow.is_some(),
            "the baseline's flow is recorded as the baseline's"
        );
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
