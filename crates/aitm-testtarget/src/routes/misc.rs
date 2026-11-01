//! Infrastructure routes (child spec D3, Task A16): `GET /flaky` and
//! `GET /slow`. Neither is a seed; both are mode-independent and exist so a
//! scanner's error ladder (5xx retries) and timing oracle (bounded delay) can
//! be proven against a deterministic origin.
//!
//! - `GET /flaky`: every third request per instance answers 500
//!   `<p>flaky</p>`; the others 200 `<p>ok</p>`. The counter is
//!   [`AppState::flaky`], shared across all listeners of one target.
//! - `GET /slow?ms=N`: sleeps `min(N, 5000)` ms, then 200 `<p>slept N</p>`
//!   with the value actually applied; a missing or non-numeric `ms` is 400.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use hyper::StatusCode;

use crate::app::{html, AppState, RequestInfo, Resp};

/// Longest delay `/slow` honours, in milliseconds; larger requests are capped
/// here so a hostile or careless caller cannot park a worker indefinitely.
const MAX_SLOW_MS: u64 = 5000;

/// Dispatch `/flaky` and `/slow`; `None` lets the router fall through.
pub(crate) async fn route(info: &RequestInfo, state: &Arc<AppState>) -> Option<Resp> {
    if info.method != "GET" {
        return None;
    }
    match info.path.as_str() {
        "/flaky" => Some(flaky(state)),
        "/slow" => Some(slow(info).await),
        _ => None,
    }
}

/// Every third request per instance fails with 500.
fn flaky(state: &Arc<AppState>) -> Resp {
    let n = state.flaky.fetch_add(1, Ordering::SeqCst) + 1;
    if n.is_multiple_of(3) {
        html(
            StatusCode::INTERNAL_SERVER_ERROR,
            "<p>flaky</p>".to_string(),
        )
    } else {
        html(StatusCode::OK, "<p>ok</p>".to_string())
    }
}

/// Sleep for the clamped `ms` query parameter, then report what was applied.
async fn slow(info: &RequestInfo) -> Resp {
    let Some(ms) = info.query_param("ms").as_deref().and_then(clamp_ms) else {
        return html(
            StatusCode::BAD_REQUEST,
            "<p>ms must be a non-negative integer</p>".to_string(),
        );
    };
    tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    html(StatusCode::OK, format!("<p>slept {ms}</p>"))
}

/// Parse a `/slow` delay and cap it at [`MAX_SLOW_MS`]. `None` when `raw` is
/// not a non-negative decimal integer (so `-1`, `abc` and `` are 400s).
fn clamp_ms(raw: &str) -> Option<u64> {
    raw.parse::<u64>().ok().map(|ms| ms.min(MAX_SLOW_MS))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use http_body_util::BodyExt;
    use hyper::StatusCode;

    use super::*;
    use crate::log::ControlLog;
    use crate::seed::SeedMode;

    fn fresh() -> Arc<AppState> {
        let log = ControlLog::new(SeedMode::Vulnerable);
        Arc::new(AppState::new(SeedMode::Vulnerable, log))
    }

    /// `GET target` through this module's `route`; returns (status, body).
    async fn get(state: &Arc<AppState>, target: &str) -> (StatusCode, String) {
        let info = RequestInfo::test_request("GET", target, &[], b"");
        let resp = route(&info, state)
            .await
            .unwrap_or_else(|| panic!("{target} is routed by misc"));
        let status = resp.status();
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("full body")
            .to_bytes();
        (
            status,
            String::from_utf8(body.to_vec()).expect("utf-8 body"),
        )
    }

    #[tokio::test]
    async fn flaky_every_third() {
        let state = fresh();
        let mut statuses = Vec::new();
        let mut bodies = Vec::new();
        for _ in 0..6 {
            let (status, body) = get(&state, "/flaky").await;
            statuses.push(status.as_u16());
            bodies.push(body);
        }
        assert_eq!(statuses, [200, 200, 500, 200, 200, 500]);
        assert_eq!(
            bodies,
            [
                "<p>ok</p>",
                "<p>ok</p>",
                "<p>flaky</p>",
                "<p>ok</p>",
                "<p>ok</p>",
                "<p>flaky</p>"
            ]
        );
    }

    #[tokio::test]
    async fn slow_caps_at_5000() {
        let state = fresh();
        let started = Instant::now();
        let (status, body) = get(&state, "/slow?ms=20").await;
        assert!(
            started.elapsed() >= Duration::from_millis(20),
            "slept only {:?}",
            started.elapsed()
        );
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "<p>slept 20</p>");

        // The cap is asserted on the pure helper so the test never waits 5 s.
        assert_eq!(clamp_ms("99999"), Some(5000));
        assert_eq!(clamp_ms("5000"), Some(5000));
        assert_eq!(clamp_ms("0"), Some(0));
        assert_eq!(clamp_ms("abc"), None);
        assert_eq!(clamp_ms(""), None);
        assert_eq!(clamp_ms("-1"), None);

        let (status, body) = get(&state, "/slow?ms=abc").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.contains("ms"),
            "400 body names the bad parameter: {body}"
        );
        let (status, _) = get(&state, "/slow").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn other_paths_fall_through() {
        let state = fresh();
        let info = RequestInfo::test_request("GET", "/", &[], b"");
        assert!(route(&info, &state).await.is_none());
        let info = RequestInfo::test_request("GET", "/flakyness", &[], b"");
        assert!(route(&info, &state).await.is_none());
    }
}
