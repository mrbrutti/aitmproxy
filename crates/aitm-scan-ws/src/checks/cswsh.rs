//! The `cswsh` check — cross-site WebSocket hijacking (task 9 of the T4 plan).
//!
//! Re-dials the captured handshake with a foreign `Origin` while keeping the
//! session cookies (the host replays them), and reads whether the upgrade still
//! completes and still produces the authenticated conversation. A server that
//! accepts any `Origin` and answers the same way it answers the real site is
//! open to cross-site WebSocket hijacking (CWE-1385): any page the victim
//! visits can open the same authenticated socket.
//!
//! The check acts only on the `origin` handshake-header point; on any other
//! point it returns `Clean` with a reason, because the whole test is "what does
//! a foreign `Origin` change". It stops before any dial on cancellation, an
//! exhausted budget or a passed deadline, treats a connect error as
//! `Inconclusive`, and never lets a cookie or any header value reach the detail
//! or the evidence (the differing-reply excerpt goes through
//! [`aitm_core::redact::scrub_text`] then [`Evidence::excerpt`]).

use std::sync::{Arc, OnceLock};

use aitm_core::redact::scrub_text;
use aitm_scan_model::{
    Check, CheckCost, CheckMeta, CheckOrigin, CheckScope, Confidence, Evidence, InsertionKind,
    InsertionPoint, Intensity, LaneKind, Outcome, Payload, PayloadMode, ProbeHost, ProbeResponse,
    Technique, Verdict,
};
use futures::future::BoxFuture;

use crate::checks::common;

/// The catalogue identifier, also the suffix of the manual `check.cswsh` verb.
pub const ID: &str = "cswsh";

/// The foreign `Origin` the check dials with: a reserved TLD that can never be a
/// legitimate origin of the target, so a completed upgrade is unambiguous.
const FOREIGN_ORIGIN: &str = "https://attacker.invalid";

/// Cross-site WebSocket hijacking.
pub struct Cswsh;

/// The `cswsh` check as a trait object for the lane's `checks()` list.
#[must_use]
pub fn check() -> Arc<dyn Check> {
    Arc::new(Cswsh)
}

impl Check for Cswsh {
    fn meta(&self) -> &CheckMeta {
        static META: OnceLock<CheckMeta> = OnceLock::new();
        META.get_or_init(|| CheckMeta {
            id: ID.to_string(),
            name: "Cross-site WebSocket hijacking".to_string(),
            class: "cswsh".to_string(),
            lanes: vec![LaneKind::Ws],
            kinds: vec![InsertionKind::WsHandshakeHeader],
            intensity: Intensity::Light,
            cost: CheckCost::Light,
            technique: Technique::Handshake,
            severity: aitm_poc::Severity::High,
            confidence_max: Confidence::Certain,
            needs_baseline: true,
            wants_traits: None,
            targets_session: false,
            scope: CheckScope::Point,
            cwe: Some(1385),
            description:
                "Re-dials the handshake with a foreign Origin and the session cookies to see \
                 whether the server still completes the authenticated WebSocket."
                    .to_string(),
            remediation: Some(
                "Validate the Origin header on the WebSocket upgrade and reject cross-site \
                 origins, or require a per-session CSRF token the attacker page cannot read."
                    .to_string(),
            ),
            origin: CheckOrigin::Native,
        })
    }

    fn run<'a>(
        &'a self,
        point: &'a InsertionPoint,
        host: &'a dyn ProbeHost,
    ) -> BoxFuture<'a, Verdict> {
        Box::pin(async move {
            if point.name != "origin" {
                return common::clean("not the Origin point", Evidence::default());
            }
            if let Some(reason) = common::stop_reason(host) {
                return common::inconclusive(reason, Vec::new());
            }

            let baseline = match host.baseline().await {
                Ok(response) => response,
                Err(e) => return common::connect_error(&e, Vec::new()),
            };

            if let Some(reason) = common::stop_reason(host) {
                return common::inconclusive(reason, Vec::new());
            }

            let probe = match host.probe(&foreign_origin_payload()).await {
                Ok(response) => response,
                Err(e) => return common::connect_error(&e, Vec::new()),
            };

            if probe.status != Some(101) {
                let status = probe
                    .status
                    .map_or_else(|| "none".to_string(), |code| code.to_string());
                return common::clean(
                    format!("upgrade refused with status {status} for a foreign Origin"),
                    evidence(Some(&baseline), Some(&probe), None),
                );
            }

            let probe_first = common::first_data_frame(&probe);
            let Some(probe_first) = probe_first else {
                return verdict(
                    Outcome::Inconclusive,
                    Confidence::Tentative,
                    "no server frame within the reply window",
                    evidence(Some(&baseline), Some(&probe), None),
                );
            };

            let baseline_first = common::first_data_frame(&baseline);
            if baseline_first.is_some_and(|frame| frame.payload == probe_first.payload) {
                verdict(
                    Outcome::Vulnerable,
                    Confidence::Certain,
                    format!(
                        "upgrade completed with Origin {FOREIGN_ORIGIN} and the first reply \
                         equals the authenticated baseline"
                    ),
                    evidence(
                        Some(&baseline),
                        Some(&probe),
                        Some("first server frame identical to baseline".to_string()),
                    ),
                )
            } else {
                let excerpt =
                    Evidence::excerpt(&scrub_text(&String::from_utf8_lossy(&probe_first.payload)));
                verdict(
                    Outcome::Vulnerable,
                    Confidence::Firm,
                    format!(
                        "upgrade completed with Origin {FOREIGN_ORIGIN} and a reply arrived that \
                         differs from the baseline"
                    ),
                    evidence(Some(&baseline), Some(&probe), Some(excerpt)),
                )
            }
        })
    }
}

/// The payload that replaces the `Origin` header with a foreign one.
fn foreign_origin_payload() -> Payload {
    Payload {
        value: FOREIGN_ORIGIN.to_string(),
        mode: PayloadMode::Replace,
        bytes: None,
    }
}

/// Evidence linking the probe and baseline flows the host recorded (empty under
/// `issues_only`, where the engine re-records from `held_flows()`), with
/// `payload: None` — a handshake check sends no field payload.
fn evidence(
    baseline: Option<&ProbeResponse>,
    probe: Option<&ProbeResponse>,
    matched: Option<String>,
) -> Evidence {
    Evidence {
        payload: None,
        matched,
        probe_flows: probe
            .and_then(|response| response.flow)
            .into_iter()
            .collect(),
        baseline_flow: baseline.and_then(|response| response.flow),
        ..Evidence::default()
    }
}

/// A verdict with no PoC hint (no `ws:` PoC step exists in v2; plan call 19).
fn verdict(
    outcome: Outcome,
    confidence: Confidence,
    detail: impl Into<String>,
    evidence: Evidence,
) -> Verdict {
    Verdict {
        outcome,
        confidence,
        evidence,
        detail: detail.into(),
        poc_hint: None,
        location: None,
        more: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use aitm_scan_model::{Check, Confidence, Outcome};
    use futures::SinkExt;
    use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
    use tokio_tungstenite::tungstenite::http::StatusCode;
    use tokio_tungstenite::tungstenite::Message;

    use super::{check, Cswsh};
    use crate::testing::{
        handshake_header, host_for, ws_server, HandshakeDecision, ServerConn, TestJob,
    };

    /// The authenticated greeting the seeded target sends right after the
    /// upgrade when the session cookie is present.
    const GREETING: &str = r#"{"type":"hello","user":"alice"}"#;

    /// The seeded "vulnerable" target: completes any upgrade and greets with the
    /// authenticated frame whenever the session cookie rode along.
    async fn greet_handler(conn: ServerConn) {
        if conn.header("cookie").is_some() {
            let mut ws = conn.ws().await;
            let _ = ws.send(Message::text(GREETING)).await;
        }
    }

    /// Completes any upgrade but answers a *different* frame for a foreign
    /// Origin; the authenticated greeting only for the real site's Origin.
    async fn differing_handler(conn: ServerConn) {
        let foreign = conn.header("origin") != Some("https://app.test");
        let mut ws = conn.ws().await;
        let reply = if foreign { r#"{"ok":false}"# } else { GREETING };
        let _ = ws.send(Message::text(reply)).await;
    }

    /// Like [`differing_handler`] but the foreign-Origin reply carries the
    /// session cookie value, so the redaction of the Firm excerpt is tested.
    async fn leaking_handler(conn: ServerConn) {
        let foreign = conn.header("origin") != Some("https://app.test");
        let mut ws = conn.ws().await;
        let reply = if foreign {
            "sid=s3cr3t-cookie"
        } else {
            GREETING
        };
        let _ = ws.send(Message::text(reply)).await;
    }

    /// Never writes: a silent server on both baseline and probe.
    async fn silent_handler(conn: ServerConn) {
        let _ = conn.header("origin");
    }

    /// A patched target: 403 on any Origin other than the real site's.
    fn rejects_foreign_origin() -> HandshakeDecision {
        // The `Err` half is tungstenite's own `ErrorResponse`; the
        // `HandshakeDecision` contract fixes it, so it cannot be boxed away.
        #[allow(clippy::result_large_err)]
        let decide = move |request: &Request| -> Result<Response, ErrorResponse> {
            let origin = request
                .headers()
                .get("origin")
                .and_then(|value| value.to_str().ok());
            if origin == Some("https://app.test") {
                Ok(
                    tokio_tungstenite::tungstenite::handshake::server::create_response(request)
                        .expect("a 101 base response"),
                )
            } else {
                let mut response = ErrorResponse::new(Some("forbidden".to_string()));
                *response.status_mut() = StatusCode::FORBIDDEN;
                Err(response)
            }
        };
        Arc::new(decide)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn vulnerable_server_accepts_any_origin() {
        let (transport, log) = ws_server(None, greet_handler);
        let job = TestJob::new(100);
        let host = host_for("origin", &job, transport);

        let verdict = check().run(host.point(), &host).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Vulnerable, Confidence::Certain)
        );
        assert!(
            verdict.detail.contains("attacker.invalid"),
            "detail must name the foreign Origin: {}",
            verdict.detail
        );
        assert_eq!(
            handshake_header(&log, 1, "origin").as_deref(),
            Some("https://attacker.invalid"),
            "the probe dial carries the foreign Origin"
        );
        assert_eq!(
            handshake_header(&log, 1, "cookie").as_deref(),
            Some("sid=s3cr3t-cookie"),
            "the probe dial keeps the session cookie"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patched_server_rejects_foreign_origin() {
        let (transport, _log) = ws_server(Some(rejects_foreign_origin()), greet_handler);
        let job = TestJob::new(100);
        let host = host_for("origin", &job, transport);

        let verdict = check().run(host.point(), &host).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Clean, Confidence::Tentative)
        );
        assert!(
            verdict.detail.contains("403"),
            "detail must name the refusal status: {}",
            verdict.detail
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn different_reply_is_firm() {
        let (transport, _log) = ws_server(None, differing_handler);
        let job = TestJob::new(100);
        let host = host_for("origin", &job, transport);

        let verdict = check().run(host.point(), &host).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Vulnerable, Confidence::Firm)
        );
        assert!(
            verdict.detail.contains("differs from the baseline"),
            "detail must say the reply differed: {}",
            verdict.detail
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn silent_server_is_inconclusive() {
        let (transport, _log) = ws_server(None, silent_handler);
        let job = TestJob::new(100);
        let host = host_for("origin", &job, transport);

        let verdict = check().run(host.point(), &host).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Inconclusive, Confidence::Tentative)
        );
        assert!(
            verdict.detail.contains("no server frame"),
            "detail must say no frame arrived: {}",
            verdict.detail
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn non_origin_point_is_clean() {
        let (transport, log) = ws_server(None, greet_handler);
        let job = TestJob::new(100);
        let host = host_for("cookie", &job, transport);

        let verdict = check().run(host.point(), &host).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Clean, Confidence::Tentative)
        );
        assert!(
            verdict.detail.contains("not the Origin point"),
            "detail must say why it did not act: {}",
            verdict.detail
        );
        assert_eq!(
            log.connections(),
            0,
            "a non-Origin point must not dial at all"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn differing_reply_with_a_cookie_is_scrubbed() {
        let (transport, _log) = ws_server(None, leaking_handler);
        let job = TestJob::new(100);
        let host = host_for("origin", &job, transport);

        let verdict = check().run(host.point(), &host).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Vulnerable, Confidence::Firm)
        );
        assert!(
            !format!("{verdict:?}").contains("s3cr3t-cookie"),
            "the cookie value must never reach the verdict: {verdict:?}"
        );
    }

    #[test]
    fn meta_is_the_fixed_catalogue_entry() {
        let meta = Cswsh.meta();
        assert_eq!(meta.id, "cswsh");
        assert_eq!(meta.class, "cswsh");
        assert_eq!(meta.cwe, Some(1385));
        assert_eq!(meta.severity, aitm_poc::Severity::High);
        assert_eq!(meta.confidence_max, Confidence::Certain);
        assert!(meta.needs_baseline);
    }
}
