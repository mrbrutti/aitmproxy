//! Linux lane: `/proc/net/tcp{,6}` rows → socket inode → `/proc/<pid>/fd`.
//!
//! The parsers are plain string functions and are not cfg-gated, so they build
//! and test on every host; the `/proc` walk in `scan` is Linux-only in
//! production but takes its `/proc` root as a path, so it is built and
//! fixture-tested on every host under `cfg(test)` (spec, Summary item 8).

pub(crate) mod parse;
#[cfg(any(target_os = "linux", test))]
pub(crate) mod scan;
