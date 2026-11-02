//! Linux lane: `/proc/net/tcp{,6}` rows → socket inode → `/proc/<pid>/fd`.
//!
//! The parsers are plain string functions and are not cfg-gated, so they build
//! and test on every host; only the `/proc` walk (plan Task 4) is Linux-only.

pub(crate) mod parse;
