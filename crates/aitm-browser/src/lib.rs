//! `aitm-browser` — embedded headless browser driver, SSRF guard, browser.* commands.
//!
//! The driver trait and its types (`BrowserDriver`, `ClickTarget`, `NavOutcome`,
//! `BrowserConfig`, `SsrfPolicy`) live in `aitm-core`; this crate implements the
//! driver over chromiumoxide/CDP for three engines — the bundled obscura fork
//! as a managed child (`ObscuraDriver`), system Chromium (`ChromeDriver`), and
//! system Firefox with a throwaway profile (`FirefoxDriver`) — selected by
//! `BrowserConfig.engine` in [`launch`], and owns the SSRF guard and the
//! commands.

mod commands;
mod config;
mod driver;
pub mod firefox;
pub mod obscura;
mod ssrf;

use std::path::Path;
use std::sync::Arc;

use aitm_core::BrowserEngine;

pub use aitm_core::{BrowserDriver, ClickTarget, NavOutcome};
pub use commands::{register_browser_commands, BrowserPlugin};
pub use config::{BrowserConfig, SsrfPolicy};
pub use driver::ChromeDriver;
pub use firefox::FirefoxDriver;
pub use obscura::{ObscuraDriver, ObscuraProcess, ProbeInfo};
pub use ssrf::{check_url, HostResolver, ResolvedTarget, SsrfGuard, StdSsrfGuard, SystemResolver};

/// What `main` holds: a shareable driver plus the one owner that can close it.
pub struct LaunchedBrowser {
    /// Handed to the `browser.*` commands; clones may outlive the owner.
    pub driver: Arc<dyn BrowserDriver>,
    closer: Closer,
}

/// The engine-specific close path behind [`LaunchedBrowser::close`].
enum Closer {
    Obscura(Arc<ObscuraDriver>),
    Chrome(Arc<ChromeDriver>),
    Firefox(Arc<FirefoxDriver>),
}

impl LaunchedBrowser {
    /// Graceful shutdown — obscura: `ObscuraDriver::close` (CDP close, SIGTERM,
    /// SIGKILL after `stop_timeout`); Chrome: `ChromeDriver::close`. Works while
    /// command handlers still hold `driver` clones; their next call fails.
    pub async fn close(self) -> anyhow::Result<()> {
        let Self { driver, closer } = self;
        drop(driver);
        match closer {
            Closer::Obscura(driver) => driver.shutdown().await,
            Closer::Chrome(driver) => driver.shutdown().await,
            Closer::Firefox(driver) => driver.shutdown().await,
        }
    }
}

/// Launch the engine `config.engine` selects. `ca_cert` is the proxy CA's
/// certificate **file**: obscura takes it as `--ca-cert` and Firefox imports it
/// into its throwaway profile; Chrome trusts the proxy via `ignore_cert_errors`
/// instead and ignores it.
pub async fn launch_owned(
    config: &BrowserConfig,
    ca_cert: &Path,
) -> anyhow::Result<LaunchedBrowser> {
    match config.engine {
        BrowserEngine::Obscura => {
            let driver = Arc::new(ObscuraDriver::launch(config, ca_cert).await?);
            Ok(LaunchedBrowser {
                driver: driver.clone(),
                closer: Closer::Obscura(driver),
            })
        }
        BrowserEngine::Chrome => {
            let driver = Arc::new(ChromeDriver::launch(config).await?);
            Ok(LaunchedBrowser {
                driver: driver.clone(),
                closer: Closer::Chrome(driver),
            })
        }
        BrowserEngine::Firefox => {
            let driver = Arc::new(FirefoxDriver::launch(config, ca_cert).await?);
            Ok(LaunchedBrowser {
                driver: driver.clone(),
                closer: Closer::Firefox(driver),
            })
        }
    }
}

/// [`launch_owned`] for callers that never close explicitly (tests, the PoC
/// runner): the engine is torn down when the last clone of the driver drops.
pub async fn launch(
    config: &BrowserConfig,
    ca_cert: &Path,
) -> anyhow::Result<Arc<dyn BrowserDriver>> {
    Ok(launch_owned(config, ca_cert).await?.driver)
}
