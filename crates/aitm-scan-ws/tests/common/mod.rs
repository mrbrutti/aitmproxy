//! What the two live-proof test binaries share.
//!
//! Compiled into each of them through `mod common;`, never into the library:
//! a process spawner, an environment variable and a `println!` are test
//! scaffolding and have no business in shipped code (quality finding N2,
//! security re-review Minor).

pub mod live;
