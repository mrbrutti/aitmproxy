//! Task 18: the chromiumoxide-backed `BrowserDriver`.
//!
//! AC10 and AC11 need a real Chromium/Chrome binary. They are part of the
//! default suite but gated at run time on `AITM_CHROME=1` (like the soak test's
//! `AITM_SOAK`), so `cargo test` stays fast and hermetic where no browser is
//! installed, and we opt in explicitly when we want to exercise the browser
//! (this binary's two Chrome tests self-serialize, so no `--test-threads=1`):
//!
//! ```text
//! AITM_CHROME=1 cargo test -p aitm-browser --test browser
//! ```

use aitm_browser::{BrowserConfig, BrowserDriver, ChromeDriver};
use aitm_core::Value;

const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";

/// The Chromium-backed tests are part of the default suite but inert unless
/// `AITM_CHROME=1` is set (mirrors the soak test's `AITM_SOAK`), so `cargo test`
/// stays fast and hermetic where no browser is installed.
fn chromium_enabled() -> bool {
    if std::env::var_os("AITM_CHROME").is_none() {
        eprintln!("skipped; set AITM_CHROME=1 to run the Chromium-backed test");
        return false;
    }
    true
}

/// Serialize this binary's Chromium tests so only one headless Chrome runs at a
/// time — reliable under default test parallelism, no `--test-threads=1` needed.
fn chrome_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    &LOCK
}

fn config_for_proxy(proxy: &str) -> BrowserConfig {
    BrowserConfig {
        proxy_addr: proxy.parse().expect("socket addr"),
        ..BrowserConfig::default()
    }
}

/// AC11 — `screenshot` returns a PNG and `eval` returns a value from the page.
#[tokio::test]
async fn primitives() {
    if !chromium_enabled() {
        return;
    }
    let _serial = chrome_lock().lock().await;
    let driver = ChromeDriver::launch(&config_for_proxy("127.0.0.1:0"))
        .await
        .expect("launch headless Chromium");

    let png = driver.screenshot().await.expect("screenshot");
    assert!(!png.is_empty());
    assert_eq!(&png[..PNG_MAGIC.len()], PNG_MAGIC);

    let two = driver.eval("1+1").await.expect("eval");
    assert_eq!(two, Value::Int(2));

    let dom = driver.get_dom().await.expect("get_dom");
    assert!(dom.contains("<html"), "outer HTML: {dom}");
}

/// AC10 — the browser launches with the proxy upstream and navigates through it.
///
/// The full assertion ("the page's requests appear as captured `HttpFlow`s")
/// needs `HttpModule` from the sibling `aitm-proto-http`, which is not a
/// dependency of this crate; that half is consolidated in the Task 29 e2e test.
/// Here (mirroring the Task 19 permitted-navigation test): one loopback listener
/// doubles as the browser's `--proxy-server` and answers the absolute-form
/// proxied request with 200. `--proxy-bypass-list=<-loopback>` (set in the launch
/// args) forces even a loopback target through the proxy, so the navigation must
/// open a connection here — which is what we assert. The navigation is bounded by
/// the driver's `nav_timeout`, so the test fails rather than hangs if it does not.
#[tokio::test]
async fn navigate_routes_through_proxy() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    if !chromium_enabled() {
        return;
    }
    let _serial = chrome_lock().lock().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind proxy listener");
    let proxy = listener.local_addr().expect("local addr");

    // The listener is the browser's proxy: record the dial and answer 200 so the
    // navigation commits instead of erroring (which could make Chrome retry/abort).
    let dialed = Arc::new(AtomicBool::new(false));
    let seen = dialed.clone();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            seen.store(true, Ordering::SeqCst);
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await;
            let body = "<html><body>ok</body></html>";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        }
    });

    let driver = ChromeDriver::launch(&config_for_proxy(&proxy.to_string()))
        .await
        .expect("launch headless Chromium");

    let url = format!("http://127.0.0.1:{}/", proxy.port());
    driver
        .navigate(&url)
        .await
        .expect("navigate through the proxy");

    assert!(
        dialed.load(Ordering::SeqCst),
        "browser never dialed the proxy"
    );
}
