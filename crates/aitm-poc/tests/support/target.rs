//! The bundled vulnerable + patched reflected-XSS test target (M1 deliverable).
//!
//! A minimal HTTP app exposing `GET /search?q=...`. In [`TargetMode::Vulnerable`]
//! the `q` value is reflected into the HTML body unescaped; in
//! [`TargetMode::Patched`] it is HTML-escaped (reusing the production
//! `html_escape` helper). The pair is what makes a `poc.run` pass against the
//! vulnerable build and fail against the patched one (AC14/AC-L2, driven later).
//!
//! Test/dev-only: it lives under `tests/` and is never linked into the `aitm`
//! binary. `spawn` leaks a background runtime thread for the lifetime of the test
//! process, which is intentional for a fixture.
//!
//! Some helpers here are consumed by later waves (Task 24's runner tests), so not
//! every item is exercised by Task 27's own test.
#![allow(dead_code)]

use std::convert::Infallible;
use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;

/// Whether the target reflects `q` unescaped (vulnerable) or escapes it (patched).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetMode {
    Vulnerable,
    Patched,
}

/// Start the target on an ephemeral loopback port and return its address.
///
/// The server runs on its own single-threaded Tokio runtime in a background
/// thread; the bound address is returned synchronously so callers can connect
/// immediately.
pub fn spawn(mode: TargetMode) -> SocketAddr {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build target runtime");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
                .await
                .expect("bind target listener");
            let addr = listener.local_addr().expect("target local addr");
            tx.send(addr).expect("report target addr");
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let io = TokioIo::new(stream);
                tokio::spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service_fn(move |req| handle(req, mode)))
                        .await;
                });
            }
        });
    });
    rx.recv().expect("receive target addr")
}

async fn handle(
    req: Request<Incoming>,
    mode: TargetMode,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let raw_q = req
        .uri()
        .query()
        .and_then(|query| query_param(query, "q"))
        .unwrap_or_default();

    let reflected = match mode {
        TargetMode::Vulnerable => raw_q,
        TargetMode::Patched => aitm_poc::dsl::html_escape(&raw_q),
    };

    let body = format!("<html><body><h1>Results for {reflected}</h1></body></html>");
    Ok(Response::new(Full::new(Bytes::from(body))))
}

/// Extract and percent-decode a query parameter value by key.
fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| percent_decode(v))
    })
}

/// Minimal application/x-www-form-urlencoded decode (`%XX` and `+` → space).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi * 16 + lo) as u8);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
