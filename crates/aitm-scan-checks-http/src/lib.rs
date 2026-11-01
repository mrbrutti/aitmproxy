//! `aitm-scan-checks-http` — scanner v2 native HTTP checks.
//!
//! Owned by track **T3** of the scanner v2 design
//! (`docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-design.md`, section
//! **D8.2**). This crate contributes native checks to the HTTP lane's catalogue,
//! not a second `http` lane, so its registration slot is [`checks`] rather than
//! `lane()` (spec amendment of 2026-10-31, recorded as A16).
//!
//! Track T1a handed over the skeleton: the crate exists, is a workspace member,
//! and exposes the final [`checks`] signature the binary already calls, so T3
//! flips the body and edits no shared file (spec D1). [`checks`] now returns
//! the ten native checks of D8.2, in id order:
//!
//! | Technique | Checks | Module |
//! |---|---|---|
//! | Boolean differential | `sqli-boolean` | [`sqli_boolean`] |
//! | Blind timing | `sqli-time`, `cmdi-time` | [`blind_timing`] |
//! | Reflection | `xss-reflected` | [`xss`] |
//! | Redirect | `open-redirect` | [`redirect`] |
//! | Observe-only HTTP/2 | `h2-settings-observe`, `h2-pseudo-header-validation`, `h2-header-crlf-tolerance`, `h2-cl-te-downgrade-indicator`, `h2-rapid-reset-mitigation` | [`h2_observe`] |
//!
//! A check's `class` carries the taxonomy token rather than its id, so the two
//! SQL-injection techniques (and the Rhai `sqli` script beside them) dedupe
//! into one issue, while the five h2 observations keep five distinct classes
//! and stay five issues (spec D6, session call S3).
//!
//! The layout is one module per technique, plus two shared, dependency-light
//! toolboxes every technique draws on:
//!
//! - [`timing`] — the least-squares [`timing::TimingOracle`] behind every blind
//!   time-based technique. It is the same algorithm the Rhai host function
//!   `probe.timing_fit` exposes (spec D4, "Timing without `sleep`"), so both
//!   halves of the catalogue agree on what "correlated" means.
//! - [`matching`] — bounded response matching. Every body a check reads is
//!   capped at [`aitm_scan_model::MAX_MATCH_BODY`] and every excerpt it quotes
//!   is capped by [`aitm_scan_model::Evidence::excerpt`], so a hostile response
//!   cannot grow an issue without limit.

#![forbid(unsafe_code)]

pub mod matching;
pub mod timing;
mod url;

pub mod blind_timing;
mod catalogue;
pub mod h2_observe;
pub mod redirect;
pub mod sqli_boolean;
pub mod xss;

pub use catalogue::checks;

// The catalogue slot's agreement with the design — the ten ids, the metadata
// shape and the `class` tokens — is pinned in `tests/catalogue.rs`, which reads
// `checks()` through the public API exactly as `crates/aitm/src/wire.rs` does.
