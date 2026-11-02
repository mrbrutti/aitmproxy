//! Help as a product (spec D15; plan wave 2, Tasks 10–14): the pages behind
//! `aitm --help`, `aitm <group>`, `aitm <group> <verb> --help` and the
//! `web`/`tui`/`operator-token` modes, built from the schema-only registry in
//! [`crate::describe`] and rendered by `aitm_term::help` for stdout's
//! capabilities. Nothing on this path creates a file or directory, opens a
//! log, spawns a process or binds (plan rule 12).
//!
//! The four leaves, addressed by path (`help::request::…`):
//!
//! - `request`: recognising a help request in argv.
//! - `catalog`: the static text — group purposes and footers, the examples
//!   table, the top-page rows.
//! - `pages`: the page builders and `render`.
//! - `answer`: from a request to a rendered page, a typed usage error, or
//!   "not help".
//!
//! This file is written by Task 8 and never edited again in wave 2 (the
//! plan's C1 discipline: parallel coders never share a root file).

pub mod answer;
pub mod catalog;
pub mod pages;
pub mod request;
