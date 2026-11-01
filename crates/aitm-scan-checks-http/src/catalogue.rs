//! The native check lists this crate contributes to the HTTP lane's catalogue.
//!
//! There are two slots, because five of the ten checks open a raw HTTP/2
//! connection of their own instead of probing through the lane's guarded
//! client (coordinator decision of 2026-11-01, option A):
//!
//! - [`checks_with`] takes the job's SSRF policy and the engine's scope guard
//!   and returns **all ten**, with the five h2 checks built over a runner that
//!   checks every address it resolves against both before it dials;
//! - [`checks`] — the slot the binary calls today — returns **nothing** in
//!   this PR. The binary collects the catalogue through
//!   `checks_with(policy, guard)` in a follow-up PR once the engine lands;
//!   until then the slot stays empty, so no native check is reachable from
//!   the binary and `crates/aitm/src/wire.rs`'s skeleton test keeps
//!   asserting zero (split-PR decision of the final F6 pass).
//!
//! An ungated raw h2 probe therefore cannot be built through a slot at all:
//! there is no constructor that omits the gate.

use std::sync::Arc;

use aitm_core::{ScopeRateGuard, SsrfPolicy};
use aitm_scan_model::Check;

use crate::h2_observe::{h2_checks, RealRawH2Runner};
use crate::{blind_timing, redirect, sqli_boolean, xss};

/// The ungated slot, which `crates/aitm/src/wire.rs::collect_native_checks`
/// calls today: **empty** in this PR.
///
/// The binary collects the catalogue through [`checks_with`] — with the
/// job's live `SsrfPolicy` and the engine's `ScopeRateGuard` — in a follow-up
/// PR once the engine lands. Until then this slot stays empty, so no native
/// check is reachable from the binary, and `wire.rs`'s
/// `skeleton_lane_slots_are_empty_today` keeps asserting zero (split-PR
/// decision of the final F6 pass, 2026-11-01). The five gate-free checks are
/// not offered here either: a slot the binary can reach without the gate
/// would be the one place the two halves of the catalogue could diverge.
#[must_use]
pub fn checks() -> Vec<Arc<dyn Check>> {
    Vec::new()
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
