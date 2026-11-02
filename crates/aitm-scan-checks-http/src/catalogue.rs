//! The native check list this crate contributes to the HTTP lane's catalogue.
//!
//! One slot, [`checks_with`]: it takes the operator's SSRF policy and the
//! proxy's scope guard and returns **all ten** checks of spec D8.2, with the
//! five h2 checks built over a runner that checks every address it resolves
//! against both before it dials (coordinator decision of 2026-11-01, option
//! A). `crates/aitm/src/wire.rs::collect_native_checks` calls it once at
//! startup with `cfg.browser.ssrf` and a guard bound to the proxy's (T3 PR
//! 2a), so every native check is live in the binary and every raw HTTP/2
//! probe is gated. There is no gate-free slot: a constructor that omitted the
//! gate would be the one place the binary could reach a raw probe without it.

use std::sync::Arc;

use aitm_core::{ScopeRateGuard, SsrfPolicy};
use aitm_scan_model::Check;

use crate::h2_observe::{h2_checks, RealRawH2Runner};
use crate::{blind_timing, redirect, sqli_boolean, xss};

/// This crate's native HTTP checks: the ten of spec D8.2, in id order.
///
/// `crates/aitm/src/wire.rs` calls this once at startup, with the operator's
/// `SsrfPolicy` (`browser.ssrf`) and a `ScopeRateGuard` bound to the proxy's
/// own guard, and hands what it gets back to the scanner's native slot. Each call builds fresh checks, so the
/// per-instance state a check keeps — the h2 checks' once-per-authority guard
/// — is never shared between two catalogues.
///
/// The five observe-only h2 checks share one [`RealRawH2Runner`], so they
/// share its connection handling. It verifies with `TlsVerify::AcceptAny`
/// (plan call **B5**): these checks exist to observe how an origin answers at
/// the frame level, and a scan target's certificate is routinely self-signed
/// or expired, which is the proxy's own trust posture for a scan and not a
/// judgement about the origin. The probes send no `Cookie`, `Authorization`
/// or session header, so an accepted certificate carries no secret — and
/// `ssrf` plus `guard` are checked against every address the target's name
/// resolves to, immediately before the dial.
#[must_use]
pub fn checks_with(ssrf: SsrfPolicy, guard: Arc<dyn ScopeRateGuard>) -> Vec<Arc<dyn Check>> {
    let runner = Arc::new(RealRawH2Runner::with_ssrf(ssrf, guard));
    let mut all: Vec<Arc<dyn Check>> = vec![
        blind_timing::cmdi_time(),
        blind_timing::sqli_time(),
        redirect::check(),
        sqli_boolean::check(),
        xss::check(),
    ];
    all.extend(h2_checks(runner));
    all.sort_by(|a, b| a.meta().id.cmp(&b.meta().id));
    all
}
