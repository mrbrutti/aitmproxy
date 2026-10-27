//! Task 18: the chromiumoxide-backed `BrowserDriver`.
//!
//! AC10 and AC11 need a Chromium binary, which this environment does not have;
//! they are `#[ignore]`d and run with `cargo test -- --ignored` where one exists.

use aitm_browser::{BrowserConfig, BrowserDriver, ChromeDriver};
use aitm_core::Value;

const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";

fn config_for_proxy(proxy: &str) -> BrowserConfig {
    BrowserConfig {
        proxy_addr: proxy.parse().expect("socket addr"),
        ..BrowserConfig::default()
    }
}

/// AC11 — `screenshot` returns a PNG and `eval` returns a value from the page.
#[tokio::test]
#[ignore = "needs Chromium"]
async fn primitives() {
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
/// Here: a proxy listener on loopback is the browser's `--proxy-server`, and a
/// navigation through it must reach the driver and return a final URL.
#[tokio::test]
#[ignore = "needs Chromium and the sibling aitm-proto-http"]
async fn navigate_routes_through_proxy() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind proxy listener");
    let proxy = listener.local_addr().expect("local addr");

    let driver = ChromeDriver::launch(&config_for_proxy(&proxy.to_string()))
        .await
        .expect("launch headless Chromium");

    // Chromium must open its connection to the proxy, not the origin.
    let accepted = tokio::spawn(async move { listener.accept().await.is_ok() });
    let _ = driver.navigate("http://example.test/").await;
    assert!(
        accepted.await.expect("join"),
        "browser never dialed the proxy"
    );
}
