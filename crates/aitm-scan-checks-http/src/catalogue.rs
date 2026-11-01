//! The native check lists this crate contributes to the HTTP lane's catalogue.
//!
//! There are two slots, because five of the ten checks open a raw HTTP/2
//! connection of their own instead of probing through the lane's guarded
//! client (coordinator decision of 2026-11-01, option A):
//!
//! - [`checks_with`] takes the job's SSRF policy and the engine's scope guard
//!   and returns **all ten**, with the five h2 checks built over a runner that
//!   checks every address it resolves against both before it dials;
//! - [`checks`] returns **only the five** that dial nothing of their own.
//!
//! An ungated raw h2 probe therefore cannot be built through a slot at all:
//! there is no constructor that omits the gate.

use std::sync::Arc;

use aitm_core::{ScopeRateGuard, SsrfPolicy};
use aitm_scan_model::Check;

use crate::h2_observe::{h2_checks, RealRawH2Runner};
use crate::{blind_timing, redirect, sqli_boolean, xss};

/// The native checks that need no gate of their own: the five that place a
/// payload through [`aitm_scan_model::ProbeHost`] and open no socket.
///
/// A caller with no SSRF policy and no scope guard to hand — a test, a tool
/// listing the catalogue — gets these and nothing else. For the whole
/// catalogue, see [`checks_with`].
#[must_use]
pub fn checks() -> Vec<Arc<dyn Check>> {
    let mut all: Vec<Arc<dyn Check>> = vec![
        blind_timing::cmdi_time(),
        blind_timing::sqli_time(),
        redirect::check(),
        sqli_boolean::check(),
        xss::check(),
    ];
    all.sort_by(|a, b| a.meta().id.cmp(&b.meta().id));
    all
}

/// This crate's native HTTP checks: the ten of spec D8.2, in id order.
///
/// `crates/aitm/src/wire.rs` calls this once at startup, with the job's live
/// `SsrfPolicy` and the engine's `ScopeRateGuard`, and adds what it gets back
/// to the HTTP lane's catalogue. Each call builds fresh checks, so the
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
    let mut all = checks();
    all.extend(h2_checks(runner));
    all.sort_by(|a, b| a.meta().id.cmp(&b.meta().id));
    all
}
