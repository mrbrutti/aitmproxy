//! `aitm-proto-l4` — authorized raw-L4 / packet MITM.
//!
//! Raw-packet capture, scapy-style craft + guarded inject, send-and-receive, and
//! Linux in-path packet interception for **authorized** L4 robustness testing of
//! an in-scope target. Everything that writes to the wire or issues a mangling
//! verdict passes a single guarded choke point gated by a deny-by-default
//! `L4Guard`. The crate never edits `aitm-core`.
//!
//! This is the crate foundation (M5 Task 1): config and scope/guard value types.
#![forbid(unsafe_code)]

pub mod config;
pub mod craft;
pub mod guard;
pub mod types;
