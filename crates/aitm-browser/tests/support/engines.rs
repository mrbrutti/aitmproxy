//! Engine parametrization for the real-browser tests (M2 Task 25, M2-AC8).
//!
//! Included by `#[path]` from the test binaries that drive a real engine
//! (`aitm-browser`'s `browser.rs` and `ssrf.rs`, `aitm`'s
//! `e2e_reflected_xss.rs`), so the gating lives in one place: a test loops
//! over [`engines`] and launches each via `aitm_browser::launch`. With neither
//! variable set the list is empty and the test is inert, keeping the default
//! `cargo test` hermetic (the pattern of the soak test's `AITM_SOAK`).

use std::net::SocketAddr;
use std::path::PathBuf;

use aitm_core::{BrowserConfig, BrowserEngine, ObscuraConfig, SsrfPolicy};

/// The engines the environment enables, in a fixed order: `Chrome` when
/// `AITM_CHROME` is set, `Obscura` when `AITM_OBSCURA` is set. Prints the skip
/// notice when neither is.
pub fn engines() -> Vec<BrowserEngine> {
    let mut engines = Vec::new();
    if std::env::var_os("AITM_CHROME").is_some() {
        engines.push(BrowserEngine::Chrome);
    }
    if std::env::var_os("AITM_OBSCURA").is_some() {
        engines.push(BrowserEngine::Obscura);
    }
    if engines.is_empty() {
        eprintln!(
            "skipped; set AITM_CHROME=1 and/or AITM_OBSCURA=1 (with AITM_OBSCURA_BIN) \
             to run the browser-backed test"
        );
    } else {
        // Visible under `--nocapture`: which engines this run exercised.
        eprintln!("engines enabled: {engines:?}");
    }
    engines
}

/// A `BrowserConfig` for `engine` routed through `proxy`, with the obscura
/// binary taken from `AITM_OBSCURA_BIN` (unset → the discovery order).
///
/// Every caller points the engine at a **loopback** test fixture, so the config
/// permits private/loopback navigation (`block_private = false`). Since audit I15
/// (938c798), the obscura engine is given `--allow-private-network` only when the
/// policy permits private targets; without it obscura refuses a loopback
/// navigation and the nav times out. The proxy's SSRF connector stays the
/// authoritative per-connection gate (it only forwards in-scope origins), and the
/// strict-policy *omits-the-flag* behaviour is unit-tested directly in
/// `obscura_spawn.rs`, not here.
pub fn config_for(engine: BrowserEngine, proxy: SocketAddr) -> BrowserConfig {
    BrowserConfig {
        engine,
        obscura: ObscuraConfig {
            binary: std::env::var_os("AITM_OBSCURA_BIN").map(PathBuf::from),
            ..ObscuraConfig::default()
        },
        proxy_addr: proxy,
        ssrf: SsrfPolicy {
            block_private: false,
            ..SsrfPolicy::default()
        },
        ..BrowserConfig::default()
    }
}
