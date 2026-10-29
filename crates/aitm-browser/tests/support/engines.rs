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

use aitm_core::{
    engine_may_reach_private, BrowserConfig, BrowserEngine, ObscuraConfig, ScopeEntry, SsrfPolicy,
};

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
/// These tests drive loopback targets (the proxy listener doubles as the origin
/// on `127.0.0.1`). They run under the **strict default** SSRF policy and
/// authorize that target the real operator way — a scoped loopback host — so the
/// engine's `--allow-private-network` flag is lifted via policy ∪ scope (audit
/// I15), never by flipping `block_private`. Mirrors what the launch site (and the
/// production `main`) computes with [`engine_may_reach_private`].
pub fn config_for(engine: BrowserEngine, proxy: SocketAddr) -> BrowserConfig {
    let ssrf = SsrfPolicy::default();
    let scope = [ScopeEntry {
        host: proxy.to_string(),
    }];
    BrowserConfig {
        engine,
        obscura: ObscuraConfig {
            binary: std::env::var_os("AITM_OBSCURA_BIN").map(PathBuf::from),
            allow_private: engine_may_reach_private(&ssrf, &scope),
            ..ObscuraConfig::default()
        },
        proxy_addr: proxy,
        ssrf,
        ..BrowserConfig::default()
    }
}
