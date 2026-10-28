//! M4 Task 13 — the Firefox engine behind the unchanged `BrowserDriver`, and
//! Review Focus #5 (a browser captures only because it was pointed at
//! aitmproxy's custom proxy, and nothing it does touches the default profile or
//! the OS trust store).
//!
//! Both tests need a real Firefox and are gated at run time behind `AITM_FIREFOX`
//! (the pattern of `AITM_OBSCURA`/`AITM_CHROME`/`AITM_SOAK`): with the variable
//! unset the tests skip inertly, so the default `cargo test` stays hermetic.
//! `AITM_FIREFOX_BIN` overrides the binary; trusting the CA into the throwaway
//! profile also needs `certutil` (NSS tools) on `PATH`.
//!
//! ```text
//! AITM_FIREFOX=1 [AITM_FIREFOX_BIN=/path/to/firefox] cargo test -p aitm-browser --test firefox
//! ```

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use aitm_browser::{BrowserDriver, FirefoxDriver};
use aitm_core::{BrowserConfig, BrowserEngine, FirefoxConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";

/// Set unless `AITM_FIREFOX` is present; prints the skip notice and signals the
/// caller to return early, keeping the default suite hermetic.
fn firefox_enabled() -> bool {
    if std::env::var_os("AITM_FIREFOX").is_some() {
        true
    } else {
        eprintln!(
            "skipped; set AITM_FIREFOX=1 (and AITM_FIREFOX_BIN, plus certutil on PATH) \
             to run the Firefox-backed test"
        );
        false
    }
}

/// Serialize the real-Firefox tests: one mutates the process-global `HOME`, and
/// both drive a browser, so they must not overlap.
fn firefox_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    &LOCK
}

/// The checked-in `aitm-ca` fixture PEM, handed to the driver as the CA whose
/// trust goes into the throwaway profile (`certutil` reads a real cert file).
fn ca_cert_fixture() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../aitm-ca/tests/fixtures/ca.crt")
        .canonicalize()
        .expect("aitm-ca fixture ca.crt")
}

/// A `BrowserConfig` for Firefox routed through `proxy`, with the binary from
/// `AITM_FIREFOX_BIN` (unset → the `firefox` default resolved on `PATH`).
fn firefox_config(proxy: SocketAddr) -> BrowserConfig {
    BrowserConfig {
        engine: BrowserEngine::Firefox,
        firefox: FirefoxConfig {
            binary: std::env::var_os("AITM_FIREFOX_BIN")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("firefox")),
            ..FirefoxConfig::default()
        },
        proxy_addr: proxy,
        ..BrowserConfig::default()
    }
}

/// A loopback listener that stands in as the engine's proxy, answering every
/// request with `body`/200. Returns its address and the accepted-connection
/// count, so a navigation that routed through it is observable.
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

/// AC-M4-12 (Firefox leg) — Firefox, pointed at aitmproxy's custom proxy by its
/// throwaway profile, routes a navigation through that proxy (so the request is
/// captured) and produces a valid PNG screenshot.
#[tokio::test]
async fn firefox_captures_through_custom_proxy() {
    if !firefox_enabled() {
        return;
    }
    let _serial = firefox_lock().lock().await;
    let (proxy, accepted) = serve_as_proxy("<html><body>ok</body></html>").await;
    let ca_cert = ca_cert_fixture();

    let before = accepted.load(Ordering::SeqCst);
    let driver = FirefoxDriver::launch(&firefox_config(proxy), &ca_cert)
        .await
        .unwrap_or_else(|err| panic!("launch firefox: {err:#}"));

    let url = format!("http://127.0.0.1:{}/", proxy.port());
    driver
        .navigate(&url)
        .await
        .unwrap_or_else(|err| panic!("navigate through the proxy: {err:#}"));

    assert!(
        accepted.load(Ordering::SeqCst) > before,
        "firefox never dialed the custom proxy"
    );

    let png = driver
        .screenshot()
        .await
        .unwrap_or_else(|err| panic!("screenshot: {err:#}"));
    assert!(!png.is_empty(), "empty screenshot");
    assert_eq!(&png[..PNG_MAGIC.len()], PNG_MAGIC, "not a PNG");

    driver.close().await.expect("close firefox");
}

/// Review Focus #5 — the launched profile is the throwaway temp one, it is
/// removed after the run, and nothing writes the Firefox default profile under a
/// redirected `HOME` (the OS proxy and OS trust store are likewise never
/// touched: routing and trust live in the throwaway profile alone).
#[tokio::test]
async fn firefox_uses_throwaway_profile_only() {
    if !firefox_enabled() {
        return;
    }
    let _serial = firefox_lock().lock().await;

    // Point HOME at an empty sandbox: a default-profile write would land here.
    let sandbox_home =
        std::env::temp_dir().join(format!("aitm-firefox-home-{}", std::process::id()));
    std::fs::create_dir_all(&sandbox_home).expect("create sandbox home");
    let prev_home = std::env::var_os("HOME");
    std::env::set_var("HOME", &sandbox_home);

    let (proxy, _) = serve_as_proxy("<html><body>ok</body></html>").await;
    let ca_cert = ca_cert_fixture();

    let driver = FirefoxDriver::launch(&firefox_config(proxy), &ca_cert)
        .await
        .unwrap_or_else(|err| panic!("launch firefox: {err:#}"));

    let profile = driver.profile_dir().to_path_buf();
    assert!(
        profile.starts_with(std::env::temp_dir()),
        "profile {profile:?} is not under the OS temp dir"
    );
    assert!(profile.exists(), "profile dir should exist while running");

    // The default profile roots Firefox would use under HOME must be untouched.
    for leaf in [
        ".mozilla",
        "Library/Application Support/Firefox",
        "Library/Application Support/Mozilla",
    ] {
        let path = sandbox_home.join(leaf);
        assert!(
            !path.exists(),
            "firefox wrote a default-profile path under HOME: {path:?}"
        );
    }

    driver.close().await.expect("close firefox");
    assert!(
        !profile.exists(),
        "throwaway profile {profile:?} was not removed after the run"
    );

    // Restore HOME and clean the sandbox.
    match prev_home {
        Some(h) => std::env::set_var("HOME", h),
        None => std::env::remove_var("HOME"),
    }
    let _ = std::fs::remove_dir_all(&sandbox_home);
}
