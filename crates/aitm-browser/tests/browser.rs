//! Tasks 18 and 25: the chromiumoxide-backed `BrowserDriver`, over both engines.
//!
//! Platform AC10/AC11 and M2-AC8/M2-AC13 need a real engine. The tests are part
//! of the default suite but gated at run time: `AITM_CHROME=1` adds system
//! Chrome, `AITM_OBSCURA=1` (with `AITM_OBSCURA_BIN`) adds the forked obscura;
//! each test loops over the enabled engines (`support/engines.rs`) and skips
//! inertly when neither is set, so `cargo test` stays fast and hermetic where
//! no browser is installed (this binary's real-browser tests self-serialize,
//! so no `--test-threads=1`):
//!
//! ```text
//! AITM_CHROME=1 AITM_OBSCURA=1 AITM_OBSCURA_BIN=/path/to/obscura cargo test -p aitm-browser --test browser
//! ```

#[path = "support/engines.rs"]
mod engines;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use aitm_browser::ClickTarget;
use aitm_core::{BrowserEngine, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use engines::{config_for, engines};

const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";

/// A page with a button and an input: the click/type half of M2-AC13 asserts
/// the state they change via `eval`.
const FIXTURE_PAGE: &str = "<html><body>\
    <button id=\"btn\" onclick=\"window.__clicked = true\">go</button>\
    <input id=\"in\">\
    </body></html>";

/// Serialize this binary's real-browser tests so only one engine runs at a
/// time — reliable under default test parallelism, no `--test-threads=1` needed.
fn browser_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    &LOCK
}

/// The CA certificate handed to `launch`: obscura needs a real PEM on
/// `--ca-cert` (it fails fast on anything else) and Chrome ignores it, so the
/// checked-in `aitm-ca` fixture serves both engines.
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

/// A loopback listener that doubles as the engine's proxy (Chrome:
/// `--proxy-server` with `<-loopback>` bypassed; obscura: `--proxy`, which has
/// no bypass list), answering every absolute-form request with `body` and 200.
/// Returns its address and the count of connections it accepted.
async fn serve_as_proxy(body: &'static str) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind proxy listener");
    let addr = listener.local_addr().expect("local addr");
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            });
        }
    });
    (addr, accepted)
}

/// Platform AC11 / M2-AC13 — per engine: `screenshot` is a PNG, `eval` returns
/// a value from the page, `get_dom` is the page's HTML, and `click` / `type`
/// change page state observable through `eval`.
#[tokio::test]
async fn primitives() {
    let engines = engines();
    if engines.is_empty() {
        return;
    }
    let _serial = browser_lock().lock().await;
    let (proxy, _) = serve_as_proxy(FIXTURE_PAGE).await;
    let ca_cert = ca_cert_fixture();

    for engine in engines {
        let driver = ok(
            engine,
            "launch",
            aitm_browser::launch(&config_for(engine, proxy), &ca_cert).await,
        );
        let url = format!("http://127.0.0.1:{}/", proxy.port());
        ok(
            engine,
            "navigate to the fixture",
            driver.navigate(&url).await,
        );

        let png = ok(engine, "screenshot", driver.screenshot().await);
        assert!(!png.is_empty(), "[{engine:?}] empty screenshot");
        assert_eq!(&png[..PNG_MAGIC.len()], PNG_MAGIC, "[{engine:?}] not a PNG");

        let two = ok(engine, "eval 1+1", driver.eval("1+1").await);
        assert_eq!(two, Value::Int(2), "[{engine:?}] eval 1+1");

        let dom = ok(engine, "get_dom", driver.get_dom().await);
        assert!(dom.contains("<html"), "[{engine:?}] outer HTML: {dom}");

        ok(
            engine,
            "click #btn",
            driver.click(ClickTarget::Selector("#btn".into())).await,
        );
        let clicked = ok(
            engine,
            "eval __clicked",
            driver.eval("window.__clicked").await,
        );
        assert_eq!(
            clicked,
            Value::Bool(true),
            "[{engine:?}] click did not run the handler"
        );

        ok(
            engine,
            "type into #in",
            driver.type_text("#in", "abc").await,
        );
        let typed = ok(
            engine,
            "eval #in value",
            driver.eval("document.querySelector('#in').value").await,
        );
        assert_eq!(typed, Value::Str("abc".into()), "[{engine:?}] typed text");
    }
}

/// Platform AC10 / M2-AC8 — per engine: the browser launches with the proxy
/// upstream and navigates through it.
///
/// The full assertion ("the page's requests appear as captured `HttpFlow`s")
/// needs `HttpModule` from the sibling `aitm-proto-http`, which is not a
/// dependency of this crate; that half lives in the `aitm` e2e test. Here the
/// loopback listener is the engine's proxy, so a navigation to a loopback
/// target must open a connection on it — which is what we assert, bounded by
/// the driver's `nav_timeout` so the test fails rather than hangs.
#[tokio::test]
async fn navigate_routes_through_proxy() {
    let engines = engines();
    if engines.is_empty() {
        return;
    }
    let _serial = browser_lock().lock().await;
    let (proxy, accepted) = serve_as_proxy("<html><body>ok</body></html>").await;
    let ca_cert = ca_cert_fixture();

    for engine in engines {
        let before = accepted.load(Ordering::SeqCst);
        let driver = ok(
            engine,
            "launch",
            aitm_browser::launch(&config_for(engine, proxy), &ca_cert).await,
        );

        let url = format!("http://127.0.0.1:{}/", proxy.port());
        ok(
            engine,
            "navigate through the proxy",
            driver.navigate(&url).await,
        );

        assert!(
            accepted.load(Ordering::SeqCst) > before,
            "[{engine:?}] browser never dialed the proxy"
        );
    }
}
