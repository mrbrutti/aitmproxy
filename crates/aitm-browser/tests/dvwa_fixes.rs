//! Live full-stack checks for the DVWA tool-fix pass (plan
//! `2026-10-29-dvwa-tool-fixes`, Tasks 8–9). The retry and bounded-wait logic
//! is proven hermetically in `driver.rs`'s unit tests; these drive a real
//! engine and are `#[ignore]`d, so the default `cargo test` stays hermetic:
//!
//! ```text
//! AITM_OBSCURA=1 AITM_OBSCURA_BIN=/path/to/obscura \
//!   cargo test -p aitm-browser --test dvwa_fixes -- --ignored
//! ```
//!
//! With `AITM_CHROME=1` set the same checks run against system Chrome.

#[path = "support/engines.rs"]
mod engines;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use aitm_browser::ClickTarget;
use aitm_core::{BrowserEngine, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use engines::{config_for, engines};

/// The CA certificate handed to `launch`: obscura needs a real PEM on
/// `--ca-cert` and Chrome ignores it, so the `aitm-ca` fixture serves both.
fn ca_cert_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../aitm-ca/tests/fixtures/ca.crt")
        .canonicalize()
        .expect("aitm-ca fixture ca.crt")
}

/// Unwrap a primitive's result, naming the engine on failure.
fn ok<T>(engine: BrowserEngine, what: &str, result: anyhow::Result<T>) -> T {
    result.unwrap_or_else(|err| panic!("[{engine:?}] {what}: {err:#}"))
}

/// A loopback listener that doubles as the engine's proxy and answers by
/// request path: `/next` gets `next_body`, everything else `index_body`.
async fn serve_as_proxy(index_body: &'static str, next_body: &'static str) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind proxy listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]);
                let body = if head.lines().next().is_some_and(|l| l.contains("/next")) {
                    next_body
                } else {
                    index_body
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            });
        }
    });
    addr
}

/// AC10 (T5), live half: the very first primitive on a fresh session is an
/// `eval` with no `navigate` before it; it must return the value, not
/// `-32601 Cannot find context with specified id`.
#[tokio::test]
#[ignore = "needs a real engine: AITM_OBSCURA=1 AITM_OBSCURA_BIN=... (or AITM_CHROME=1)"]
async fn eval_without_navigate() {
    let engines = engines();
    assert!(!engines.is_empty(), "enable an engine to run this check");
    let proxy = serve_as_proxy("<html><body>idx</body></html>", "").await;
    let ca_cert = ca_cert_fixture();

    for engine in engines {
        let driver = ok(
            engine,
            "launch",
            aitm_browser::launch(&config_for(engine, proxy), &ca_cert).await,
        );
        let two = ok(
            engine,
            "eval 1+1 with no navigate",
            driver.eval("1+1").await,
        );
        assert_eq!(two, Value::Int(2), "[{engine:?}] eval before any navigate");
    }
}

/// The page a click navigates away from: a link to `/next`, plus a button
/// that only runs page script (the no-navigation half of AC11).
const INDEX_PAGE: &str = "<html><body>\
    <a id=\"go\" href=\"/next\">go</a>\
    <button id=\"stay\" onclick=\"window.__stayed = true\">stay</button>\
    </body></html>";

/// What `/next` serves; `get_dom` after the click must contain the marker.
const NEXT_PAGE: &str = "<html><body><p id=\"result\">RESULT-PAGE</p></body></html>";

/// AC11 (T6), live half: `click` on a link awaits the navigation it triggers,
/// so the next `get_dom` is the post-navigation document; `click` on a button
/// that navigates nothing still returns `Ok` and the handler ran.
#[tokio::test]
#[ignore = "needs a real engine: AITM_OBSCURA=1 AITM_OBSCURA_BIN=... (or AITM_CHROME=1)"]
async fn click_then_get_dom_sees_result_page() {
    let engines = engines();
    assert!(!engines.is_empty(), "enable an engine to run this check");
    let proxy = serve_as_proxy(INDEX_PAGE, NEXT_PAGE).await;
    let ca_cert = ca_cert_fixture();

    for engine in engines {
        let driver = ok(
            engine,
            "launch",
            aitm_browser::launch(&config_for(engine, proxy), &ca_cert).await,
        );
        let url = format!("http://127.0.0.1:{}/", proxy.port());
        ok(engine, "navigate to the index", driver.navigate(&url).await);

        ok(
            engine,
            "click #stay (no navigation)",
            driver.click(ClickTarget::Selector("#stay".into())).await,
        );
        let stayed = ok(
            engine,
            "eval __stayed",
            driver.eval("window.__stayed").await,
        );
        assert_eq!(
            stayed,
            Value::Bool(true),
            "[{engine:?}] handler did not run"
        );

        ok(
            engine,
            "click #go (navigates)",
            driver.click(ClickTarget::Selector("#go".into())).await,
        );
        let dom = ok(engine, "get_dom after click", driver.get_dom().await);
        assert!(
            dom.contains("RESULT-PAGE"),
            "[{engine:?}] get_dom still shows the pre-click page: {dom}"
        );
    }
}
