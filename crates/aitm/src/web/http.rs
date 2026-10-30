//! The `aitm web` HTTP server: hyper 1 over one task per connection, routing
//! `GET /bus` (WebSocket upgrade) to the bridge, `GET /healthz` to a liveness
//! JSON, and everything else to the embedded assets. GET/HEAD only.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{self, HeaderName, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::debug;

use super::assets::{self, Resolved};
use super::{bridge, WebState};

/// Applied to every non-upgrade response. The UI is self-contained: no remote
/// scripts, styles or frames; the bus is same-origin `ws(s):`.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; \
style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; \
connect-src 'self' ws: wss:; worker-src 'self' blob:; frame-ancestors 'none'";

/// Brief pause after a failed `accept()` so a persistent error (e.g. fd
/// exhaustion) does not spin the loop at full speed.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(20);

/// How long a client may take to send its request head before the connection is
/// dropped (slowloris guard on the pre-upgrade HTTP request).
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Accept connections forever (until the future is dropped).
pub async fn serve(listener: TcpListener, state: Arc<WebState>) -> anyhow::Result<()> {
    let (_tx, rx) = watch::channel(false);
    serve_until(listener, state, rx).await
}

/// Accept connections until `shutdown` turns `true` (or its sender drops).
/// In-flight connections finish on their own tasks.
pub async fn serve_until(
    listener: TcpListener,
    state: Arc<WebState>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    // A transient accept error (ECONNABORTED, or fd exhaustion
                    // EMFILE/ENFILE) must not end the accept loop: this future
                    // is a top-level `select!` arm in `main`, so returning `Err`
                    // here would tear down the whole process — proxy, browser
                    // and MCP included. Log, back off briefly so we don't spin
                    // while fds are scarce, and keep serving.
                    debug!(error = %e, "web: accept failed; continuing");
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                    continue;
                }
            },
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
                continue;
            }
        };
        debug!(%peer, "web: connection accepted");
        let state = state.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let state = state.clone();
                async move { Ok::<_, Infallible>(router(req, &state)) }
            });
            let conn = http1::Builder::new()
                .timer(TokioTimer::new())
                // Bound how long a client may dribble request headers before the
                // upgrade (slowloris on the pre-upgrade HTTP request).
                .header_read_timeout(HEADER_READ_TIMEOUT)
                .keep_alive(true)
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades();
            if let Err(e) = conn.await {
                debug!(%peer, error = %e, "web: connection ended with an error");
            }
        });
    }
}

/// Route one request. Synchronous: asset lookups are table reads and the
/// bridge's upgrade runs on its own spawned task after the 101 goes out.
pub fn router(mut req: Request<Incoming>, state: &Arc<WebState>) -> Response<Full<Bytes>> {
    if req.method() != Method::GET && req.method() != Method::HEAD {
        let mut resp = text(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
        resp.headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
        return harden(resp);
    }
    let path = req.uri().path().to_owned();
    match path.as_str() {
        "/bus" => match bridge::handshake(&req) {
            bridge::Handshake::Accept(switching) => {
                let on_upgrade = hyper::upgrade::on(&mut req);
                tokio::spawn(bridge::run(on_upgrade, state.clone()));
                switching
            }
            bridge::Handshake::Refuse(refusal) => harden(refusal),
        },
        "/healthz" => {
            let mut resp = Response::new(Full::new(Bytes::from_static(br#"{"ok":true}"#)));
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            harden(resp)
        }
        _ => harden(asset_response(&path)),
    }
}

fn asset_response(path: &str) -> Response<Full<Bytes>> {
    match assets::resolve(path) {
        Resolved::Asset(asset) => {
            let mut resp = Response::new(Full::new(Bytes::from_static(asset.body)));
            let headers = resp.headers_mut();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(asset.content_type),
            );
            headers.insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static(asset.cache_control),
            );
            resp
        }
        Resolved::NotBuilt => {
            let mut resp = Response::new(Full::new(Bytes::from_static(
                assets::NOT_BUILT_HTML.as_bytes(),
            )));
            let headers = resp.headers_mut();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            );
            headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Resolved::NotFound => text(StatusCode::NOT_FOUND, "not found"),
    }
}

fn text(status: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(Bytes::from_static(body.as_bytes())));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}

/// The security headers every ordinary response carries.
fn harden(mut resp: Response<Full<Bytes>>) -> Response<Full<Bytes>> {
    let h = resp.headers_mut();
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    h.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    resp
}
