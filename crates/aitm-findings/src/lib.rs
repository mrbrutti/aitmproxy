//! `aitm-findings` — the persistent findings / run-history store (M4 Stream B).
//!
//! A durable, **human-readable** record of what the agent (or operator) actually
//! *found* across runs, distinct from the PoC *library* (`poc.list`, which lists
//! YAML templates) and from the F2 command-audit ring (which records
//! *invocations*). One YAML file per finding under `findings.dir`, plus an
//! append-only `runs.jsonl` run-history log. The report renderer (Task 15) and the
//! grader (Task 12) read this store; the `findings.*` commands expose it on the bus.
//!
//! Recording a finding is a separate, explicit, gated act after a passing
//! `poc.run` — `poc.*` stays unchanged and persists nothing silently (spec D8a).
//! Secrets are never copied into a record: free-text fields are redacted at the
//! store boundary (same posture as the audit ring).

pub mod commands;
pub mod record;
pub mod recorder;
pub mod report;
pub mod store;

pub use commands::FindingsPlugin;
pub use record::{FindingArtifacts, FindingFilter, FindingRecord, FindingSummary, Reproduction};
pub use recorder::DiskFindingRecorder;
pub use report::{render_index, render_report};
pub use store::{DiskFindingStore, FindingStore};
