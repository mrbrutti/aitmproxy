//! [`DiskFindingRecorder`]: the `aitm-findings` implementation of the core
//! [`aitm_core::FindingRecorder`] seam.
//!
//! The PoC runner (in `aitm-poc`, which cannot depend on this crate) builds a
//! [`FindingDraft`] for a passing `poc.run` and records it through the trait on
//! `CommandHost`. This type turns the draft into a [`FindingRecord`] — `control_passed`
//! is `None` (a `poc.run` runs no patched control) and `discovered_at`/`run_at` are
//! `now()` — and persists it via [`DiskFindingStore`] under the configured
//! `findings.dir`, so the record is indistinguishable from one made by
//! `findings.record` (same redaction, same id derivation, same `runs.jsonl` line).

use std::path::Path;
use std::time::SystemTime;

use aitm_core::{FindingDraft, FindingRecorder};

use crate::commands::parse_severity;
use crate::record::{FindingArtifacts, FindingRecord, Reproduction};
use crate::store::{DiskFindingStore, FindingStore};

/// Zero-state recorder: every call opens a [`DiskFindingStore`] over the `dir` it
/// is given, so one instance serves every configured findings directory.
#[derive(Debug, Clone, Copy, Default)]
pub struct DiskFindingRecorder;

impl FindingRecorder for DiskFindingRecorder {
    fn record(&self, draft: &FindingDraft, dir: &Path) -> anyhow::Result<String> {
        let severity = parse_severity(&draft.severity)?;
        let now = SystemTime::now();
        let record = FindingRecord {
            id: String::new(),
            title: draft.title.clone(),
            class: draft.class.clone(),
            severity,
            target: draft.target.clone(),
            discovered_at: now,
            origin: draft.origin,
            client_label: draft.client_label.clone(),
            poc_ref: draft.poc_ref.clone(),
            reproduction: Reproduction {
                passed: draft.passed,
                control_passed: None,
                run_at: now,
            },
            artifacts: FindingArtifacts {
                finding_capture: draft.finding_capture,
                poc_path: draft.poc_path.clone(),
                screenshot_path: draft.screenshot_path.clone(),
            },
            flows: draft.flows.clone(),
            notes: None,
        };
        DiskFindingStore::new(dir).record(record)
    }
}
