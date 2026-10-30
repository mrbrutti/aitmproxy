//! Scanner configuration and its budget defaults.

use std::time::Duration;

/// Budgets and gates that bound a scan run.
///
/// Every field is a hard ceiling: the scan stops at the first one it reaches,
/// so a run is always bounded in breadth, depth, request count and wall time.
#[derive(Debug, Clone, PartialEq, Eq)]
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
}
