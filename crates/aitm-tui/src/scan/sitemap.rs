//! The Site map tab's state (spec D3, D8, D11).

use aitm_scan_model::{InsertionPoint, JobId, SiteNode};

use super::ScanError;

/// Which pane of the Site map tab holds the cursor. The legacy lists (D12)
/// are walked through the same pane from Task 4 on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MapPane {
    #[default]
    Nodes,
    Points,
}

/// The `scan.sitemap` query the tab is showing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SitemapQuery {
    /// Restrict to one job (`J` toggles).
    pub job: Option<JobId>,
    /// Restrict to one target origin.
    pub target: Option<String>,
}

/// The Site map tab.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SitemapState {
    pub nodes: Vec<SiteNode>,
    pub points: Vec<InsertionPoint>,
    /// `Some` while another page can be fetched with `n`.
    pub next_cursor: Option<String>,
    pub node_cursor: usize,
    pub point_cursor: usize,
    pub pane: MapPane,
    pub query: SitemapQuery,
    /// The tick of the last `scan.sitemap` request.
    pub fetched_at_tick: u64,
    /// This tab's last error.
    pub error: Option<ScanError>,
}
