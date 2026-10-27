//! `aitm-browser` — embedded headless browser driver, SSRF guard, browser.* commands.
//!
//! The driver trait and its types (`BrowserDriver`, `ClickTarget`, `NavOutcome`,
//! `BrowserConfig`, `SsrfPolicy`) live in `aitm-core`; this crate implements the
//! driver over chromiumoxide/CDP and owns the SSRF guard and the commands.

mod commands;
mod config;
mod driver;
pub mod obscura;
mod ssrf;

pub use aitm_core::{BrowserDriver, ClickTarget, NavOutcome};
pub use commands::{register_browser_commands, BrowserPlugin};
pub use config::{BrowserConfig, SsrfPolicy};
pub use driver::ChromeDriver;
pub use obscura::{ObscuraProcess, ProbeInfo};
pub use ssrf::{check_url, HostResolver, ResolvedTarget, SsrfGuard, StdSsrfGuard, SystemResolver};
