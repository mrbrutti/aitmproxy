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
/// Empty until the checks land: filled by task 17 of the T4 plan, once tasks 9
/// to 16 have written the eight check bodies.
#[must_use]
pub fn all() -> Vec<Arc<dyn Check>> {
    Vec::new()
}
