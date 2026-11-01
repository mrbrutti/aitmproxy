//! The `ws-sql-error` check — written by task 12 of the T4 plan.
//!
//! One quote, placed in a field of a captured WebSocket message, is the whole
//! probe: a server that interpolates the field into SQL answers with its
//! database's syntax error instead of data (spec D8.3 "Checks", technique
//! `error`). The probe is inert — it reads, writes and exfiltrates nothing;
//! the only thing it changes is the quoting of one field — and the oracle is
//! the error text, not the data behind it.
//!
//! Two rules keep the verdict honest:
//!
//! - **The baseline votes first.** A target whose ordinary reply already
//!   carries a database error signature would make every payload look like a
//!   hit, so a noisy baseline ends the check `Clean` with that reason and
//!   costs no payload at all.
//! - **Evidence is ours, not the server's.** `Evidence.matched` is the
//!   signature constant from [`crate::payloads`] and `Evidence.payload` is the
//!   quote this check sent; neither the server's text nor any header value
//!   reaches the verdict (the plan's redaction rule).

use std::sync::{Arc, OnceLock};

use aitm_scan_model::{
    Check, CheckCost, CheckMeta, CheckOrigin, Confidence, Evidence, InsertionKind, InsertionPoint,
    Intensity, LaneKind, Outcome, Payload, PayloadMode, ProbeHost, ProbeResponse, Technique,
    Verdict,
};
use futures::future::BoxFuture;

use crate::checks::common;

use crate::payloads::{sql_error_signature, SQL_ERROR_PAYLOADS, SQL_ERROR_SIGNATURES};

/// The catalogue id of this check, also its `check.<id>` verb suffix.
pub const ID: &str = "ws-sql-error";

/// `ws-sql-error`: a database error signature provoked by a quote in a field.
pub struct WsSqlError;

/// This check, ready for the lane's registry.
#[must_use]
pub fn check() -> Arc<dyn Check> {
    Arc::new(WsSqlError)
}

/// The fixed catalogue entry (plan call 6), built once.
fn meta() -> &'static CheckMeta {
    static META: OnceLock<CheckMeta> = OnceLock::new();
    META.get_or_init(|| CheckMeta {
        id: ID.to_string(),
        name: "SQL error in a WebSocket reply".to_string(),
        class: "sqli".to_string(),
        lanes: vec![LaneKind::Ws],
        kinds: vec![
            InsertionKind::WsJsonValue,
            InsertionKind::WsText,
            InsertionKind::WsFormParam,
        ],
        intensity: Intensity::Medium,
        cost: CheckCost::Light,
        technique: Technique::Error,
        severity: aitm_poc::Severity::High,
        confidence_max: Confidence::Firm,
        needs_baseline: true,
        wants_traits: None,
        targets_session: false,
        cwe: Some(89),
        description:
            "Places an unbalanced quote in a WebSocket message field and reads the reply for a \
             database error signature."
                .to_string(),
        remediation: Some(
            "Use parameterised queries for values that arrive over a WebSocket, and keep database \
             error text out of client-visible replies."
                .to_string(),
        ),
        origin: CheckOrigin::Native,
    })
}

impl Check for WsSqlError {
    fn meta(&self) -> &CheckMeta {
        meta()
    }

    fn run<'a>(
        &'a self,
        point: &'a InsertionPoint,
        host: &'a dyn ProbeHost,
    ) -> BoxFuture<'a, Verdict> {
        // The point itself carries nothing this check needs: the scheduler has
        // already matched it against `meta().kinds`, and the host knows where
        // the payload goes.
        let _ = point;
        Box::pin(async move { run(host).await })
    }
}

/// The check's whole body: baseline, then one probe per payload.
async fn run(host: &dyn ProbeHost) -> Verdict {
    if let Some(reason) = common::stop_reason(host) {
        return common::inconclusive(reason, Vec::new());
    }

    let baseline = match host.baseline().await {
        Ok(response) => response,
        Err(error) => return common::connect_error(&error, Vec::new()),
    };
    if sql_error_signature(&body_text(&baseline)).is_some() {
        return clean("baseline already carries a SQL error signature", &baseline);
    }

    for payload in SQL_ERROR_PAYLOADS {
        if let Some(reason) = common::stop_reason(host) {
            return common::inconclusive(reason, Vec::new());
        }
        let probe = Payload {
            value: payload.to_string(),
            mode: PayloadMode::Replace,
            bytes: None,
        };
        let response = match host.probe(&probe).await {
            Ok(response) => response,
            Err(error) => return common::connect_error(&error, Vec::new()),
        };
        if let Some(signature) = sql_error_signature(&body_text(&response)) {
            return Verdict {
                outcome: Outcome::Vulnerable,
                confidence: Confidence::Firm,
                evidence: Evidence {
                    payload: Some(payload.to_string()),
                    matched: Some(signature.to_string()),
                    probe_flows: response.flow.into_iter().collect(),
                    baseline_flow: baseline.flow,
                    ..Evidence::default()
                },
                detail: detail_for(signature),
                poc_hint: None,
            };
        }
    }

    clean(
        "no SQL error signature in any reply to an unbalanced quote",
        &baseline,
    )
}

/// The operator-facing line for a hit, naming the signature and its DBMS.
///
/// Both halves are scanner constants from [`crate::payloads`]: the server's own
/// text never appears here.
fn detail_for(signature: &str) -> String {
    match dbms_of(signature) {
        Some(dbms) => format!("SQL error signature '{signature}' after payload ({dbms})"),
        None => format!("SQL error signature '{signature}' after payload"),
    }
}

/// The database a signature belongs to, from the table that defined it.
fn dbms_of(signature: &str) -> Option<&'static str> {
    SQL_ERROR_SIGNATURES
        .iter()
        .find(|(_, needle)| *needle == signature)
        .map(|(dbms, _)| *dbms)
}

/// The text frames of a response, as a string to match signatures in.
fn body_text(response: &ProbeResponse) -> String {
    String::from_utf8_lossy(&response.body).into_owned()
}

/// [`common::clean`] linking the baseline conversation it was reached from.
fn clean(detail: impl Into<String>, baseline: &ProbeResponse) -> Verdict {
    common::clean(
        detail,
        Evidence {
            baseline_flow: baseline.flow,
            ..Evidence::default()
        },
    )
}

#[cfg(test)]
mod tests {
    use aitm_scan_model::{Confidence, Outcome};
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    use super::{check, ID};
    use crate::testing::{echo_handler, host_for, ws_server, ServerConn, TestJob};

    /// What a MySQL-backed server leaks when an unbalanced quote reaches it.
    const MYSQL_ERROR: &str = r#"{"error":"You have an error in your SQL syntax near '''"}"#;

    /// The seeded vulnerable target: a quote in the frame provokes the database
    /// error, anything else is echoed as the patched build echoes it.
    async fn quote_leaks_sql_error(conn: ServerConn) {
        let mut ws = conn.ws().await;
        while let Some(Ok(message)) = ws.next().await {
            match message {
                Message::Text(text) => {
                    conn.record(text.as_bytes().to_vec());
                    let reply = if text.contains('\'') {
                        MYSQL_ERROR.to_string()
                    } else {
                        format!("echo:{text}")
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

    /// A target whose every reply carries the database error, quote or not.
    async fn always_sql_error(conn: ServerConn) {
        let mut ws = conn.ws().await;
        while let Some(Ok(message)) = ws.next().await {
            match message {
                Message::Text(text) => {
                    conn.record(text.as_bytes().to_vec());
                    if ws.send(Message::text(MYSQL_ERROR)).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn vulnerable_server_leaks_mysql_error() {
        let (transport, log) = ws_server(None, quote_leaks_sql_error);
        let job = TestJob::new(100);
        let host = host_for("msg", &job, transport);
        let point = host.point().clone();

        let check = check();
        let verdict = check.run(&point, &host).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Vulnerable, Confidence::Firm)
        );
        assert_eq!(
            verdict.evidence.matched.as_deref(),
            Some("you have an error in your sql syntax"),
            "matched is the signature constant, never the server's text"
        );
        assert_eq!(verdict.evidence.payload.as_deref(), Some("'"));
        assert!(
            verdict.detail.contains("SQL error signature") && verdict.detail.contains("mysql"),
            "detail: {}",
            verdict.detail
        );
        assert_eq!(
            log.connections(),
            2,
            "the baseline and the first payload only: the check stops at the first hit"
        );
        assert!(
            !format!("{verdict:?}").contains("s3cr3t-cookie"),
            "the replayed cookie must not reach a verdict: {verdict:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn patched_server_is_clean_after_three_payloads() {
        let (transport, log) = ws_server(None, echo_handler);
        let job = TestJob::new(100);
        let host = host_for("msg", &job, transport);
        let point = host.point().clone();

        let check = check();
        let verdict = check.run(&point, &host).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Clean, Confidence::Tentative)
        );
        assert_eq!(verdict.evidence.matched, None);
        assert_eq!(
            log.connections(),
            4,
            "the baseline and all three payloads were sent"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn noisy_baseline_is_clean() {
        let (transport, log) = ws_server(None, always_sql_error);
        let job = TestJob::new(100);
        let host = host_for("msg", &job, transport);
        let point = host.point().clone();

        let check = check();
        let verdict = check.run(&point, &host).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Clean, Confidence::Tentative)
        );
        assert!(
            verdict.detail.contains("baseline"),
            "detail: {}",
            verdict.detail
        );
        assert_eq!(
            log.connections(),
            1,
            "a target that always errs is not worth a payload"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn budget_zero_is_inconclusive_before_any_connect() {
        let (transport, log) = ws_server(None, quote_leaks_sql_error);
        let job = TestJob::new(0);
        let host = host_for("msg", &job, transport);
        let point = host.point().clone();

        let check = check();
        let verdict = check.run(&point, &host).await;

        assert_eq!(
            (verdict.outcome, verdict.confidence),
            (Outcome::Inconclusive, Confidence::Tentative)
        );
        assert_eq!(verdict.detail, "budget exhausted");
        assert_eq!(log.connections(), 0, "nothing is dialled without budget");
    }

    #[test]
    fn meta_is_the_catalogue_entry() {
        let check = check();
        let meta = check.meta();

        assert_eq!(meta.id, ID);
        assert_eq!(meta.id, "ws-sql-error");
        assert_eq!(meta.name, "SQL error in a WebSocket reply");
        assert_eq!(meta.class, "sqli");
        assert_eq!(meta.lanes, vec![aitm_scan_model::LaneKind::Ws]);
        assert_eq!(
            meta.kinds,
            vec![
                aitm_scan_model::InsertionKind::WsJsonValue,
                aitm_scan_model::InsertionKind::WsText,
                aitm_scan_model::InsertionKind::WsFormParam,
            ]
        );
        assert_eq!(meta.intensity, aitm_scan_model::Intensity::Medium);
        assert_eq!(meta.cost, aitm_scan_model::CheckCost::Light);
        assert_eq!(meta.technique, aitm_scan_model::Technique::Error);
        assert_eq!(meta.severity, aitm_poc::Severity::High);
        assert_eq!(meta.confidence_max, Confidence::Firm);
        assert!(meta.needs_baseline);
        assert_eq!(meta.wants_traits, None);
        assert!(!meta.targets_session);
        assert_eq!(meta.cwe, Some(89));
        assert_eq!(meta.origin, aitm_scan_model::CheckOrigin::Native);
    }
}
