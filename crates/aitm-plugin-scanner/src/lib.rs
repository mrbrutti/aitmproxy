//! `aitm-plugin-scanner` — the scanner plugin: the deterministic Stage 1
//! scanner and, from scanner v2 track T1b, the scan **engine** (spec
//! `docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-design.md`).
//!
//! The engine's modules sit one concern per file: [`config`] and [`util`] are
//! the shared ground, [`profiles`], [`issues`], [`client`], [`session`],
//! [`catalogue`], [`scheduler`] and [`reproduce_link`] the pieces a job is
//! built from, [`jobs`] and [`worker`] the job model itself, [`verbs`],
//! [`manual_check`] and [`commands`] its bus surface, and [`interim_lane`] the
//! HTTP lane the engine runs until the `aitm-scan-http` lane crate lands.

// The workspace lint already forbids `unsafe`; the attribute makes the
// promise local to the crate that handles attacker-authored bytes.
#![forbid(unsafe_code)]

pub mod catalogue;
pub mod checks;
pub mod client;
pub mod commands;
pub mod config;
pub mod crawl;
pub mod discover;
pub mod inject;
pub mod interim_lane;
pub mod issues;
pub mod jobs;
pub mod manual_check;
pub mod passive;
pub mod plugin;
pub mod profiles;
pub mod report;
pub mod reproduce;
pub mod reproduce_link;
pub mod scheduler;
pub mod session;
pub mod util;
pub mod verbs;
pub mod worker;

pub use checks::{AttackMode, CheckDefinition, Evidence, Payload};
pub use config::{Ceilings, ScannerConfig};
pub use crawl::{crawl, CrawlOutcome};
pub use discover::{enumerate, InjectionPoint, Location};
pub use inject::{inject, Confirmed, InjectOutcome};
pub use passive::{passive_checks, PassiveFinding};
pub use plugin::ScannerPlugin;
pub use report::{index_to_value, load_records};
pub use reproduce::{build_poc, record_finding};
