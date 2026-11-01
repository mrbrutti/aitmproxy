//! Scanner configuration and its budget defaults.
//!
//! [`ScannerConfig`] is the plugin's own config type. It lives outside
//! `aitm_core::Config` (spec D11, the `l4:` pattern): the binary parses the
//! `scanner:` section of the config file into it and hands it to the plugin,
//! so `aitm-core` knows nothing about the scanner.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use aitm_scan_model::ScanProfile;

/// The hard ceilings a profile is clamped to (spec D11).
///
/// A profile is the operator's dial; a ceiling is the administrator's wall. A
/// profile value above a ceiling is clamped by the engine and reported in
/// `scan.start`'s `clamped` list rather than refused, so a generous profile
/// still runs — bounded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ceilings {
    /// Maximum stimuli (probes, crawl requests, L4 cases) one job may send.
    pub probes: u32,
    /// Wall-clock ceiling for one job, in seconds.
    pub time_s: u64,
    /// Maximum L4 fuzz cases one job may send.
    pub l4_cases: u32,
    /// Maximum L4 send rate, in bytes per second.
    pub l4_bytes_per_s: u32,
    /// Maximum WebSocket frame payload one job may send, in bytes.
    pub ws_frame_bytes: u32,
    /// Maximum issues one job may record; the job stops at the ceiling.
    pub max_issues: u32,
}

impl Default for Ceilings {
    fn default() -> Self {
        Self {
            probes: 20_000,
            time_s: 7_200,
            l4_cases: 5_000,
            l4_bytes_per_s: 1_048_576,
            ws_frame_bytes: 4_194_304,
            max_issues: 4_096,
        }
    }
}

/// Budgets and gates that bound a scan run.
///
/// Every field is a hard ceiling: the scan stops at the first one it reaches,
/// so a run is always bounded in breadth, depth, request count and wall time.
///
/// `Eq` is deliberately absent: [`ScanProfile`] holds `f32` fields, so the tree
/// is only `PartialEq`.
#[derive(Debug, Clone, PartialEq)]
pub struct ScannerConfig {
    /// Maximum link depth the crawl follows from each seed.
    pub max_depth: usize,
    /// Maximum number of distinct pages the crawl visits.
    pub max_pages: usize,
    /// Maximum number of requests the whole run may issue.
    pub request_budget: usize,
    /// Wall-clock ceiling for the whole run.
    pub time_budget: Duration,
    /// Maximum payloads tried per vulnerability class per insertion point.
    pub per_class_payload_cap: usize,
    /// Whether an agent frontend may start an active scan. Deny by default.
    pub allow_agent_active: bool,
    /// Whether an agent frontend may start a job whose profile runs an L4 fuzz
    /// lane. Deny by default, and independent of `allow_agent_active`: packet
    /// and stream fuzzing is the most invasive thing the scanner does.
    pub allow_agent_l4_fuzz: bool,
    /// How many scan jobs may run at once.
    pub max_jobs: u32,
    /// How many finished jobs are kept in the registry (and listed by
    /// `scan.list`) before the oldest is dropped.
    pub history: u32,
    /// Per-check wall-clock ceiling, in seconds.
    pub check_timeout_s: u64,
    /// The hard ceilings every profile is clamped to.
    pub ceilings: Ceilings,
    /// The profile `scan.start` uses when the caller names only a `target`.
    pub default_profile: String,
    /// Profiles declared in the config file, by name. They sit between the
    /// built-ins and the profiles saved under `<findings.dir>/scan/profiles/`.
    pub profiles: BTreeMap<String, ScanProfile>,
    /// Where job, issue and profile state is written (`<dir>/scan/...`, spec
    /// D11). `None` — the default — keeps every job in memory only. The binary
    /// copies `config.findings.dir` here; it is not a file key of its own.
    pub findings_dir: Option<PathBuf>,
    /// Mirror of `features.l4.allow_agent_inject`
    /// (`crates/aitm-proto-l4/src/config.rs`), copied here by the binary so the
    /// `scan.start` L4 gate reads one struct. Not a `scanner:` file key.
    pub l4_allow_agent_inject: bool,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            max_depth: 3,
            max_pages: 200,
            request_budget: 2000,
            time_budget: Duration::from_secs(600),
            per_class_payload_cap: 25,
            allow_agent_active: false,
            allow_agent_l4_fuzz: false,
            max_jobs: 2,
            history: 50,
            check_timeout_s: 60,
            ceilings: Ceilings::default(),
            default_profile: "standard".to_string(),
            profiles: BTreeMap::new(),
            findings_dir: None,
            l4_allow_agent_inject: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn scanner_config_defaults() {
        let cfg = ScannerConfig::default();
        assert_eq!(cfg.max_depth, 3);
        assert_eq!(cfg.max_pages, 200);
        assert_eq!(cfg.request_budget, 2000);
        assert_eq!(cfg.time_budget, Duration::from_secs(600));
        assert_eq!(cfg.per_class_payload_cap, 25);
        assert!(!cfg.allow_agent_active);
    }

    /// Spec D11: the scanner v2 engine knobs the `scanner:` config section feeds.
    /// Every number here is the spec's literal default, so an operator who writes
    /// no `scanner:` section gets exactly the documented behaviour.
    #[test]
    fn scanner_config_defaults_grow() {
        let cfg = ScannerConfig::default();
        assert_eq!(cfg.max_jobs, 2);
        assert_eq!(cfg.history, 50);
        assert_eq!(cfg.check_timeout_s, 60);
        assert_eq!(
            cfg.ceilings,
            Ceilings {
                probes: 20_000,
                time_s: 7_200,
                l4_cases: 5_000,
                l4_bytes_per_s: 1_048_576,
                ws_frame_bytes: 4_194_304,
                max_issues: 4_096,
            }
        );
        assert_eq!(cfg.default_profile, "standard");
        assert!(cfg.profiles.is_empty());
        assert!(!cfg.allow_agent_l4_fuzz);
        assert!(!cfg.l4_allow_agent_inject);
        assert!(cfg.findings_dir.is_none());
    }
}
