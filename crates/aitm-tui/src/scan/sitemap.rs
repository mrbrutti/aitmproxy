//! The Site map tab's state (spec D3, D8, D11).

use aitm_scan_model::{InsertionPoint, JobId, SiteNode};

use super::{ScanError, ScanOffer};

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

/// Which lists the Site map's two panes walk: the legacy `scan.discover`
/// endpoints and injection points (D12), or the v2 `scan.sitemap` nodes and
/// points. Decided once, from the bus, so the cursor keys and `Enter` never
/// disagree (fix round A, A2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapSource {
    Legacy,
    V2,
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

impl SitemapState {
    /// The lists the panes walk on a bus offering `offer`: the v2 lists only
    /// on a v2 bus, the legacy lists otherwise (a bus with no scanner has
    /// empty legacy lists, which is the right answer too).
    pub fn source(offer: ScanOffer) -> MapSource {
        if offer == ScanOffer::V2 {
            MapSource::V2
        } else {
            MapSource::Legacy
        }
    }
}
