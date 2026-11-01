//! The native check list this crate contributes to the HTTP lane's catalogue.

use std::sync::Arc;

use aitm_scan_model::Check;

/// This crate's native HTTP checks, empty while the track is unimplemented.
///
/// `crates/aitm/src/wire.rs` calls this once at startup and adds what it gets
/// back to the HTTP lane's catalogue. The signature is final; the entries
/// arrive one technique at a time as track T3 lands them.
#[must_use]
pub fn checks() -> Vec<Arc<dyn Check>> {
    Vec::new()
}
