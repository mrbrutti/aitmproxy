//! `aitm-browser` — embedded headless browser driver, SSRF guard, browser.* commands.
//!
//! The driver trait and its types (`BrowserDriver`, `ClickTarget`, `NavOutcome`,
//! `BrowserConfig`, `SsrfPolicy`) live in `aitm-core`; this crate implements the
//! driver over chromiumoxide/CDP and owns the SSRF guard and the commands.

mod config;
mod driver;

pub use aitm_core::{BrowserDriver, ClickTarget, NavOutcome};
pub use config::{BrowserConfig, SsrfPolicy};
pub use driver::ChromeDriver;
