//! The native check list this crate contributes to the HTTP lane's catalogue.

use std::sync::Arc;

use aitm_scan_model::Check;

use crate::h2_observe::{h2_checks, RealRawH2Runner};
use crate::{blind_timing, redirect, sqli_boolean, xss};

/// This crate's native HTTP checks: the ten of spec D8.2, in id order.
///
/// `crates/aitm/src/wire.rs` calls this once at startup and adds what it gets
/// back to the HTTP lane's catalogue. Each call builds fresh checks, so the
/// per-instance state a check keeps — the h2 checks' once-per-authority guard —
/// is never shared between two catalogues.
///
/// The five observe-only h2 checks share one [`RealRawH2Runner`], so they share
/// its connection handling. It verifies with `TlsVerify::AcceptAny` (plan call
/// **B5**): these checks exist to observe how an origin answers at the frame
/// level, and a scan target's certificate is routinely self-signed or expired,
/// which is the proxy's own trust posture for a scan and not a judgement about
/// the origin. The probes send no `Cookie`, `Authorization` or session header,
/// so an accepted certificate carries no secret.
#[must_use]
pub fn checks() -> Vec<Arc<dyn Check>> {
    let runner = Arc::new(RealRawH2Runner::new());
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
