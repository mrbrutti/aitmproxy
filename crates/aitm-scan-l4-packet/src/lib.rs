//! `aitm-scan-l4-packet` — the scanner v2 L4 packet lane.
//!
//! Owned by track **T5** of the scanner v2 design
//! (`docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-design.md`, section
//! **D8.4**). The lane fuzzes IPv4/IPv6, UDP and TCP header fields and the raw
//! payload of a crafted `PacketSpec` against operator-declared L4 targets, one
//! `send_recv` per case behind the deny-by-default `L4Guard`, with a liveness
//! oracle and non-overridable ceilings.
//!
//! Ownership inside the lane: `PacketLane` ([`lane`](crate::lane)) holds an
//! `Arc<Shared>` ([`host`]) — guard, backend, case store, seed store and the
//! per-job `Arc<LaneState>` ([`state`]) — plus an `Arc<RunnerRegistry>` that maps
//! `(job id, point id)` to the one `PointRunner` that owns a point's fuzz run.
//! That key is the engine's stable job id, never `JobCtx::marker`, which mints
//! a fresh token on every call. Both checks ([`checks`]) read that single
//! cached run through the registry, so whichever check reaches a point first
//! drives the cases and the other sends nothing.
//!
//! `crates/aitm/src/wire.rs` calls [`lane`](crate::lane()) with the handles from
//! `Features::l4_shared`; both are `None` when L4 is disabled. A landed L4 lane
//! returns `Some` even then, so that `scan.start` refuses with `refused_l4`
//! rather than `lane_unavailable` (D3's refusal order, call A18).

#![forbid(unsafe_code)]

use std::sync::Arc;

use aitm_proto_l4::flow::L4FlowStore;
use aitm_proto_l4::guard::L4Guard;
use aitm_scan_model::Lane;

pub mod checks;
pub mod codec;
pub mod discover;
pub mod fields;
pub mod host;
pub mod lane;
pub mod mutate;
pub mod oracle;
pub mod plan;
pub mod rng;
pub mod state;
pub(crate) mod sync;
#[doc(hidden)]
pub mod testing;

/// The L4 packet lane, or `None` while the lane is unimplemented.
///
/// `crates/aitm/src/wire.rs` calls this once at startup with the handles from
/// `Features::l4_shared`; both are `None` when L4 is disabled. Track T5
/// replaces [`lane::build`]'s body with a lane that is `Some` even when the
/// handles are `None`, so `scan.start` refuses with `refused_l4` rather than
/// `lane_unavailable` (D3's refusal order, call A18). The signature is final.
#[must_use]
pub fn lane(
    guard: Option<Arc<L4Guard>>,
    store: Option<Arc<dyn L4FlowStore>>,
) -> Option<Arc<dyn Lane>> {
    lane::build(guard, store)
}
