//! Helper: the wire contract shared by the core and the privileged
//! packet-capture helper process (spec §5.2, §5.3).
//!
//! Pure encode/decode and pure policy. Nothing here opens a socket, spawns a
//! process or touches system state; the two ends link this one module so there
//! is a single definition of the protocol rather than two that can drift.

pub mod proto;
