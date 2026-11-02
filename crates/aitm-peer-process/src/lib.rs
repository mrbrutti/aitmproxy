//! Name the process behind an accepted loopback TCP connection.
//!
//! The core accepts a proxied connection and knows the client's loopback `ip:port`,
//! but only a capture backend (the macOS Network Extension) ever told it *which*
//! process opened it, so every `curl -x` row shows Client "—". This crate finds the
//! owner of the other end of that socket without privileges and without an
//! extension: on macOS a libproc scan of same-user processes' TCP sockets, on Linux
//! `/proc/net/tcp{,6}` → inode → `/proc/<pid>/fd`. The pid becomes a bundle
//! identifier when the executable lives in a bundle, else an executable basename;
//! the string is sanitised before it leaves the crate.
//!
//! It is a *leaf* crate so the rest of the workspace keeps
//! `unsafe_code = "forbid"`: the libproc calls need `unsafe`, and every one of them
//! lives in `macos::ffi` behind a safe, `Option`-returning wrapper.
//!
//! Everything here is **fail-closed**: any error, timeout, drained rate budget,
//! unreadable pid, or unprintable name yields `None`, never a guess. A missing
//! Client is a display gap; a wrong one is misattribution.

pub mod linux;
pub mod macos;
pub(crate) mod matching;
pub mod sanitize;
pub mod types;

pub use sanitize::sanitize;
pub use types::{Limits, ProcessKey, Tuple};
