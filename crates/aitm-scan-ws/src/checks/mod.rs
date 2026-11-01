//! The eight native WebSocket checks, one module each.
//!
//! The module tree is written by task 1 of the T4 plan; each check's body is
//! written by its own task (9 to 16) and [`all`] is filled by task 17.

use std::sync::Arc;

use aitm_scan_model::Check;

pub mod auth_bypass;
pub mod cmdi_echo;
pub mod cswsh;
pub mod oversize;
pub mod reflection;
pub mod sql_error;
pub mod ssti;
pub mod subprotocol;

/// Every native WebSocket check, in the order the lane registers them.
///
/// Handshake checks first (they need only the upgrade), then the payload
/// checks over frame content, then the two observational ones. The engine
/// filters this list by profile; the lane returns all of it.
#[must_use]
pub fn all() -> Vec<Arc<dyn Check>> {
    vec![
        cswsh::check(),
        auth_bypass::check(),
        reflection::check(),
        sql_error::check(),
        ssti::check(),
        cmdi_echo::check(),
        oversize::check(),
        subprotocol::check(),
    ]
}
