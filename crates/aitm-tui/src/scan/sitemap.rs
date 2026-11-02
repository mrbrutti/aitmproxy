//! The Site map tab's state (spec D3, D8, D11, D12) and the pure helpers the
//! reducer and the view share: the `scan.sitemap` fold, the grouped node
//! lines, the point line and the legacy `scan.discover` result read as nodes
//! and points so it renders through the same view.
//!
//! Hostile-core bounds (D6): a page is cut to [`SITEMAP_PAGE_LIMIT`] nodes
//! and points, every string the screen reads is cut to [`VALUE_MAX`] cells
//! once, when the page is folded, and the node lines are built once per fold
//! (`lines`, the display twin of `nodes`), so a frame measures and draws
//! bounded text only.

use std::collections::{HashMap, HashSet};
use std::ops::Range;

use aitm_scan_model::{
    FlowRef, InsertionKind, InsertionPoint, JobId, LaneKind, PointTrait, SiteNode, SitemapResult,
};
use serde_json::{json, Map, Value};

use super::legacy::LegacyState;
use super::profiles::{authority_of, authority_parts, default_port};
use super::{wire_token, ScanError, ScanOffer};
use crate::text::cut_to;

/// How many `Tick`s between two `scan.sitemap` refreshes while the Site map
/// is shown and a job is crawling (spec D6: forty ticks, ten seconds).
pub const SITEMAP_POLL_TICKS: u64 = 40;

/// The most nodes and the most points one `scan.sitemap` page contributes
/// (D6 hostile-core bounds; the Issues page limit, applied to both lists):
/// the rest of a longer page is dropped at fold time.
pub const SITEMAP_PAGE_LIMIT: usize = 512;

/// The most nodes, and the most points, the Site map holds across appended
/// pages (fix round G, G17; D6 hostile-core bounds; the builder's number,
/// sixteen full pages): once a fold reaches it the lists are cut there,
/// `next_cursor` is dropped and the summary says `limit reached`.
pub const SITEMAP_TOTAL_LIMIT: usize = 8192;

/// The most traits a point keeps at fold, after dedup (fix round G, G15;
/// the vocabulary has fewer, so a longer list is a hostile core's).
pub const POINT_TRAITS_MAX: usize = 8;

/// The longest `next_cursor` the TUI echoes back to the core, in bytes
/// (fix round G, G16): a longer one is dropped and recorded as an error.
pub const CURSOR_MAX: usize = 1024;

/// The detail of the uncoded error a `scan.sitemap` reply gets when its
/// `next_cursor` is over [`CURSOR_MAX`].
pub const CURSOR_TOO_LONG: &str = "next_cursor exceeds 1024 bytes";

/// The mark an audited node's line ends with (D11 `✓`; builder's glyph, flat
/// monochrome as D13 asks).
pub const AUDITED_MARK: &str = "✓";

/// The widest any string of a node or point grows before it is cut, once,
/// at fold time (D6 hostile-core bounds).
pub const SITEMAP_VALUE_MAX: usize = 200;

/// The method a legacy endpoint is listed under: the legacy crawler reaches
/// its endpoints by browser navigation, which is a GET (builder's reading of
/// D12, "one node per URL").
const LEGACY_METHOD: &str = "GET";

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

impl SitemapQuery {
    /// The `scan.sitemap` arguments (spec D6, `{query, cursor?}`): every
    /// `Some` field under its umbrella-contract name, `None` omitted, and
    /// the page cursor when one is passed.
    pub fn args(&self, cursor: Option<&str>) -> Value {
        let mut args = Map::new();
        if let Some(job) = &self.job {
            args.insert("job".into(), json!(job));
        }
        if let Some(target) = &self.target {
            args.insert("target".into(), json!(target));
        }
        if let Some(cursor) = cursor {
            args.insert("cursor".into(), json!(cursor));
        }
        Value::Object(args)
    }

    /// Whether a line for `job` is about the map this query shows: every
    /// job without a job filter, that one job with it.
    pub fn matches(&self, job: &str) -> bool {
        self.job.as_deref().is_none_or(|j| j == job)
    }

    /// `J` (D11): the job filter becomes the Jobs cursor's job (`cursor`)
    /// when none is set, else none. Returns whether the query changed, so
    /// the reducer refetches only then (fix round G, G31): `J` with no
    /// cursor job and no filter leaves it as it was.
    pub fn toggle_job(&mut self, cursor: Option<JobId>) -> bool {
        let next = match self.job {
            Some(_) => None,
            None => cursor,
        };
        let changed = next != self.job;
        self.job = next;
        changed
    }
}

/// Which lists the Site map's two panes walk: the legacy `scan.discover`
/// endpoints and injection points (D12), or the v2 `scan.sitemap` nodes and
/// points. Decided once, from the bus, so the cursor keys and `Enter` never
/// disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapSource {
    Legacy,
    V2,
}

impl From<ScanOffer> for MapSource {
    /// The lists the panes walk on a bus offering `offer`: the v2 lists only
    /// on a v2 bus, the legacy lists otherwise (a bus with no scanner has
    /// empty legacy lists, which is the right answer too).
    fn from(offer: ScanOffer) -> Self {
        if offer == ScanOffer::V2 {
            MapSource::V2
        } else {
            MapSource::Legacy
        }
    }
}

/// One node's line in the Nodes pane: its group key (`host[:port]`, the
/// header it sits under) and its text (`METHOD path_template  flows n ·
/// pts n · ✓`). `SitemapState::lines[k]` is the line of
/// `SitemapState::nodes[k]` (fix round G, G22): the fold sorts the nodes
/// into group order (every node of one host before the next host's, hosts
/// in the order they first appear), so the cursor walks what the pane
/// draws.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeLine {
    pub host: String,
    pub text: String,
}

/// The Site map tab.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SitemapState {
    /// The nodes shown, in group order ([`group_nodes`]; fix round G,
    /// G22): every `scan.sitemap` page appended so far, or on a legacy bus
    /// the `scan.discover` endpoints read as nodes
    /// ([`SitemapState::show_legacy`]; `legacy.endpoint_cursor` indexes
    /// this grouped list); strings bounded when set.
    pub nodes: Vec<SiteNode>,
    /// The nodes' display twin, index for index with `nodes`
    /// (`lines[k]` draws `nodes[k]`; `lines.len() == nodes.len()`).
    pub lines: Vec<NodeLine>,
    /// The points shown. From `scan.sitemap`: sorted so each node's points
    /// are contiguous in node order ([`SitemapState::node_points`]), then
    /// the orphans (a point naming no node of `nodes`, or none at all)
    /// last in their wire order and not drawn, kept so a point whose node
    /// arrives on a later page re-attaches (fix round G, G20). On a
    /// legacy bus: the injection points read as points, index for index
    /// with `legacy.points`. Strings bounded when set.
    pub points: Vec<InsertionPoint>,
    /// The points' display twin, index for index with `points`
    /// ([`point_line`] of each, built once at fold; fix round G, G15).
    pub point_lines: Vec<String>,
    /// Each node's range of `points`, index for index with `nodes`, built
    /// at fold so [`SitemapState::node_points`] is a lookup (G17).
    pub node_ranges: Vec<Range<usize>>,
    /// `Some` while another page can be fetched with `n`; dropped once
    /// the lists reach [`SITEMAP_TOTAL_LIMIT`] (`limit_reached`).
    pub next_cursor: Option<String>,
    /// The lists reached [`SITEMAP_TOTAL_LIMIT`] (G17): the summary says
    /// so and no further page is asked for.
    pub limit_reached: bool,
    /// The job the last `scan.sitemap` reply named as the map's (umbrella
    /// amendment 27: `{}` returns the newest job's map and says which; fix
    /// round H, H61), cut like every other string; `None` until a reply
    /// names one (an older core never does). The summary head reads it.
    pub job: Option<JobId>,
    pub node_cursor: usize,
    /// The Points cursor as an offset within the selected node's points
    /// (fix round G, G24): the shared walk runs over
    /// `node_points(node_cursor).len()`, a Nodes walk resets it and a fold
    /// clamps it, so [`SitemapState::selected_point`] is the point under
    /// it or `None` when the node has none.
    pub point_offset: usize,
    pub pane: MapPane,
    pub query: SitemapQuery,
    /// The tick the last `scan.sitemap` left on; `None` until one has.
    pub fetched_at_tick: Option<u64>,
    /// The mode of the last `scan.sitemap` that left: `n`'s page appends
    /// (D10) instead of replacing. Overwritten by every send, taken by the
    /// fold.
    pub appending: bool,
    /// This tab's last error.
    pub error: Option<ScanError>,
}

impl SitemapState {
    /// Fold a `scan.sitemap` reply (spec D10): the page replaces `nodes` and
    /// `points`, or appends to them after `n` (`appending`); `next_cursor`
    /// is the reply's. Hostile-core bounds (D6): the page is cut to
    /// [`SITEMAP_PAGE_LIMIT`] nodes and points, every string is cut to
    /// [`VALUE_MAX`] cells here, once. The nodes are then sorted into group
    /// order and the lines rebuilt index for index (fix round G, G22), the
    /// points re-ordered under them (orphans last, G20), and both cursors
    /// settled: the Nodes cursor stays on the id it was on when that node
    /// is still listed (an appended page may move its row), else it is
    /// clamped.
    ///
    /// Two more hostile-core bounds (fix round G): a `next_cursor` over
    /// [`CURSOR_MAX`] bytes is dropped and returned as an uncoded error
    /// (G16; the reducer records it); once either list reaches
    /// [`SITEMAP_TOTAL_LIMIT`] it is cut there, the cursor is dropped and
    /// `limit_reached` is set (G17).
    pub fn fold_result(&mut self, mut result: SitemapResult) -> Option<ScanError> {
        let append = std::mem::take(&mut self.appending);
        result.nodes.truncate(SITEMAP_PAGE_LIMIT);
        result.points.truncate(SITEMAP_PAGE_LIMIT);
        result.nodes.iter_mut().for_each(bound_node);
        result.points.iter_mut().for_each(bound_point);
        let selected = self.selected_node().map(|n| n.id.clone());
        if append {
            self.nodes.extend(result.nodes);
            self.points.extend(result.points);
        } else {
            self.nodes = result.nodes;
            self.points = result.points;
        }
        // The reply names the job it chose (H61); an appended page that does
        // not keeps the first page's.
        if let Some(mut job) = result.job {
            cut(&mut job);
            self.job = Some(job);
        } else if !append {
            self.job = None;
        }
        let mut error = None;
        self.next_cursor = match result.next_cursor {
            Some(c) if c.len() > CURSOR_MAX => {
                error = Some(ScanError::uncoded("scan.sitemap", CURSOR_TOO_LONG));
                None
            }
            other => other,
        };
        self.limit_reached =
            self.nodes.len() >= SITEMAP_TOTAL_LIMIT || self.points.len() >= SITEMAP_TOTAL_LIMIT;
        if self.limit_reached {
            self.nodes.truncate(SITEMAP_TOTAL_LIMIT);
            self.points.truncate(SITEMAP_TOTAL_LIMIT);
            self.next_cursor = None;
        }
        self.relist(selected);
        error
    }

    /// Sort `nodes` into group order, rebuild `lines` and the point order,
    /// and settle both cursors; `selected` is the id the Nodes cursor was
    /// on, re-found when still listed.
    fn relist(&mut self, selected: Option<String>) {
        group_nodes(&mut self.nodes);
        self.order_points();
        self.lines = node_lines(&self.nodes);
        debug_assert_eq!(
            self.lines.len(),
            self.nodes.len(),
            "lines is nodes' display twin, one per node"
        );
        let found = selected.and_then(|id| self.nodes.iter().position(|n| n.id == id));
        self.node_cursor =
            found.unwrap_or(self.node_cursor.min(self.nodes.len().saturating_sub(1)));
        self.point_offset = self
            .point_offset
            .min(self.node_points(self.node_cursor).len().saturating_sub(1));
    }

    /// On a legacy bus (D12) the lists are the `scan.discover` result read
    /// as nodes and points ([`legacy_nodes`], [`legacy_points`]): the
    /// nodes in group order like a page (`legacy.endpoint_cursor` walks
    /// them; the node's id is the endpoint URL, so `Enter` reads its flow
    /// through `legacy.endpoint_flows`), the points index for index with
    /// `legacy.points`, whose cursor the Points pane keeps walking; bounded
    /// and lined once per result, so a frame draws bounded text only. The
    /// v2 cursors, query and page cursor are not touched (a legacy bus
    /// never has them).
    pub fn show_legacy(&mut self, legacy: &LegacyState) {
        self.nodes = legacy_nodes(legacy);
        self.nodes.iter_mut().for_each(bound_node);
        group_nodes(&mut self.nodes);
        self.points = legacy_points(legacy);
        self.points.iter_mut().for_each(bound_point);
        self.point_lines = self.points.iter().map(point_line).collect();
        self.node_ranges = Vec::new();
        self.lines = node_lines(&self.nodes);
    }

    /// Sort `points` into node order (stable, so a node's points keep the
    /// core's order), the orphans last (key `nodes.len()`; fix round G,
    /// G20), so each node's points are contiguous and an orphan is never
    /// in any node's range; then build each node's range and each point's
    /// line (G15, G17). Linear in the lists: the node ids are indexed once.
    fn order_points(&mut self) {
        let last = self.nodes.len();
        let index: HashMap<&str, usize> = self
            .nodes
            .iter()
            .enumerate()
            .map(|(k, n)| (n.id.as_str(), k))
            .collect();
        let position = |p: &InsertionPoint| -> usize {
            p.site_node
                .as_deref()
                .and_then(|id| index.get(id).copied())
                .unwrap_or(last)
        };
        let mut keyed: Vec<(usize, InsertionPoint)> = std::mem::take(&mut self.points)
            .into_iter()
            .map(|p| (position(&p), p))
            .collect();
        keyed.sort_by_key(|(k, _)| *k);
        let mut ranges: Vec<Range<usize>> = Vec::with_capacity(last);
        let mut at = 0;
        for node in 0..last {
            let start = at;
            while keyed.get(at).is_some_and(|(k, _)| *k == node) {
                at += 1;
            }
            ranges.push(start..at);
        }
        self.node_ranges = ranges;
        self.points = keyed.into_iter().map(|(_, p)| p).collect();
        self.point_lines = self.points.iter().map(point_line).collect();
    }

    /// The node under the Nodes cursor, if the list has one.
    pub fn selected_node(&self) -> Option<&SiteNode> {
        self.nodes.get(self.node_cursor)
    }

    /// The range of `points` belonging to the node at `idx`: contiguous,
    /// because [`SitemapState::fold_result`] sorts them into node order,
    /// and read off `node_ranges`, built at fold. Empty (at the end of the
    /// list) when the node has none or `idx` names no node.
    pub fn node_points(&self, idx: usize) -> Range<usize> {
        self.node_ranges
            .get(idx)
            .cloned()
            .unwrap_or(self.points.len()..self.points.len())
    }

    /// The point under the Points cursor: the selected node's point at
    /// `point_offset`, `None` when the node has none (or fewer).
    pub fn selected_point(&self) -> Option<&InsertionPoint> {
        let range = self.node_points(self.node_cursor);
        if self.point_offset < range.len() {
            self.points.get(range.start + self.point_offset)
        } else {
            None
        }
    }

    /// The summary line the view draws first (D11: `12 nodes · 2 points of
    /// node-1 · n next page`): the node count, the map's job when the reply
    /// named one (`· job <id>`; H61), the selected node's point count and
    /// id, the paging hint only while a next page exists, and `limit
    /// reached` once the lists hit [`SITEMAP_TOTAL_LIMIT`] (G17).
    pub fn summary(&self) -> String {
        let mut text = format!("{} nodes", self.nodes.len());
        if let Some(job) = &self.job {
            text.push_str(&format!(" · job {job}"));
        }
        if let Some(node) = self.selected_node() {
            let n = self.node_points(self.node_cursor).len();
            text.push_str(&format!(" · {n} points of {}", node.id));
        }
        if self.next_cursor.is_some() {
            text.push_str(" · n next page");
        }
        if self.limit_reached {
            text.push_str(" · limit reached");
        }
        text
    }
}

/// Cut every string the screen reads off a node to [`SITEMAP_VALUE_MAX`]
/// cells.
fn bound_node(node: &mut SiteNode) {
    for s in [
        &mut node.id,
        &mut node.method,
        &mut node.scheme,
        &mut node.host,
        &mut node.path_template,
    ] {
        cut(s);
    }
    node.flows.truncate(SITEMAP_PAGE_LIMIT);
}

/// Cut every string the screen reads off a point to [`SITEMAP_VALUE_MAX`] cells,
/// and its traits to their distinct values, at most [`POINT_TRAITS_MAX`]
/// (fix round G, G15).
fn bound_point(point: &mut InsertionPoint) {
    let mut seen: HashSet<PointTrait> = HashSet::new();
    point.traits.retain(|t| seen.insert(*t));
    point.traits.truncate(POINT_TRAITS_MAX);
    point.traits.shrink_to_fit();
    cut(&mut point.id);
    cut(&mut point.name);
    for s in [
        point.path.as_mut(),
        point.example.as_mut(),
        point.site_node.as_mut(),
        point.method.as_mut(),
        point.url.as_mut(),
    ]
    .into_iter()
    .flatten()
    {
        cut(s);
    }
}

/// Bound a node or point string to [`SITEMAP_VALUE_MAX`] cells with its
/// control characters stripped ([`cut_to`]; fix round H, H22: the Site
/// map's strings are cleaned too).
fn cut(s: &mut String) {
    cut_to(s, SITEMAP_VALUE_MAX);
}

/// Sort `nodes` into group order (D11; fix round G, G22): every node of
/// one `host[:port]` key before the next key's, keys in the order they
/// first appear, stable inside a group (a node keeps its place among its
/// host's). The port is part of the key only when it is not the scheme's
/// default (80 for http, 443 for https).
pub fn group_nodes(nodes: &mut [SiteNode]) {
    let mut hosts: Vec<String> = Vec::new();
    let groups: Vec<usize> = nodes
        .iter()
        .map(|node| {
            let key = host_key(node);
            hosts.iter().position(|h| *h == key).unwrap_or_else(|| {
                hosts.push(key);
                hosts.len() - 1
            })
        })
        .collect();
    let mut order: Vec<usize> = (0..nodes.len()).collect();
    order.sort_by_key(|k| groups[*k]);
    // Apply the permutation in place: `order[i]` is the node that moves
    // to `i`; cycles are followed with swaps.
    let mut placed = vec![false; nodes.len()];
    for start in 0..nodes.len() {
        if placed[start] {
            continue;
        }
        let mut i = start;
        loop {
            placed[i] = true;
            let from = order[i];
            if from == start {
                break;
            }
            nodes.swap(i, from);
            i = from;
        }
    }
}

/// The node lines of `nodes`, one per node, index for index (D11; fix
/// round G, G22): its `host[:port]` key and its text. `nodes` is expected
/// in group order ([`group_nodes`]), so the pane opens a host header
/// wherever the key changes.
pub fn node_lines(nodes: &[SiteNode]) -> Vec<NodeLine> {
    nodes
        .iter()
        .map(|node| NodeLine {
            host: host_key(node),
            text: node_text(node),
        })
        .collect()
}

/// `host[:port]`, the port only when it is not the scheme's default.
fn host_key(node: &SiteNode) -> String {
    if node.port == default_port(&node.scheme) {
        node.host.clone()
    } else {
        format!("{}:{}", node.host, node.port)
    }
}

/// `METHOD path_template  flows n · pts n · ✓` (D11; `pts` for points,
/// the mark only on an audited node). The method is padded to four cells
/// so `GET` and `POST` paths line up, as the mockup draws them.
fn node_text(node: &SiteNode) -> String {
    let mut text = format!(
        "{:<4} {}  flows {} · pts {}",
        node.method,
        node.path_template,
        node.flows.len(),
        node.points
    );
    if node.audited {
        text.push_str(" · ");
        text.push_str(AUDITED_MARK);
    }
    text
}

/// The point columns' widths (`kind name path traits example`; builder's
/// widths from the D11 mockup): a short value is padded to its column, a
/// longer one runs past it and shifts that row only, since the strings are
/// already bounded.
const POINT_COLUMNS: [usize; 4] = [12, 14, 24, 8];

/// `kind name path traits example` (D11): the wire tokens of the kind and
/// the traits (comma-joined), `-` for a missing path, traits or example,
/// and the example verbatim (it is redacted at the source).
pub fn point_line(p: &InsertionPoint) -> String {
    let traits = if p.traits.is_empty() {
        "-".to_string()
    } else {
        p.traits
            .iter()
            .map(wire_token)
            .collect::<Vec<_>>()
            .join(",")
    };
    point_columns(
        &wire_token(&p.kind),
        &p.name,
        p.path.as_deref().unwrap_or("-"),
        &traits,
        p.example.as_deref().unwrap_or("-"),
    )
}

/// The Points pane's column header, laid out as [`point_line`] is.
pub fn point_header() -> String {
    point_columns("kind", "name", "path", "traits", "example")
}

fn point_columns(kind: &str, name: &str, path: &str, traits: &str, example: &str) -> String {
    let [kw, nw, pw, tw] = POINT_COLUMNS;
    format!("{kind:<kw$} {name:<nw$} {path:<pw$} {traits:<tw$} {example}")
}

/// The legacy `scan.discover` result as site nodes (D12): one node per
/// endpoint URL (its own id), `GET` ([`LEGACY_METHOD`]), the URL's scheme,
/// host, port (the scheme's default when none) and path; `flows` the
/// `endpoint_flows` link when it is a flow id in the wire form (a UUID;
/// the legacy fixture's `f50` is not one, so it counts no flow there);
/// `points` the injection points found in that flow.
pub fn legacy_nodes(legacy: &LegacyState) -> Vec<SiteNode> {
    legacy
        .endpoints
        .iter()
        .map(|url| {
            let (scheme, rest) = url
                .split_once("://")
                .map_or(("http", url.as_str()), |(s, r)| (s, r));
            let authority = authority_of(rest);
            let path = match &rest[authority.len()..] {
                "" => "/",
                p => p,
            };
            let (host, port) =
                authority_parts(authority).unwrap_or_else(|_| (authority.to_string(), None));
            let port = port.unwrap_or_else(|| default_port(scheme));
            let flow = legacy.endpoint_flows.get(url);
            let flows: Vec<FlowRef> = flow.and_then(|id| flow_ref(id)).into_iter().collect();
            let points = flow.map_or(0, |id| {
                legacy.points.iter().filter(|p| p.flow == *id).count()
            });
            SiteNode {
                id: url.clone(),
                method: LEGACY_METHOD.to_string(),
                scheme: scheme.to_string(),
                host,
                port,
                path_template: path.to_string(),
                flows,
                params: Vec::new(),
                auth: false,
                points: u32::try_from(points).unwrap_or(u32::MAX),
                audited: false,
            }
        })
        .collect()
}

/// A legacy flow id as the contract's [`FlowRef`]: `Some` when it is a
/// UUID in the wire form, read through `FlowId`'s parser (fix round G,
/// G27), never through JSON.
fn flow_ref(id: &str) -> Option<FlowRef> {
    id.parse().ok().map(FlowRef)
}

/// The legacy injection points as insertion points (D12), in the order the
/// result listed them: the legacy `location` token as the kind (`redirect`,
/// the legacy crawler's "a parameter whose value is a URL", is a `query`
/// point with the `url` trait; a token this TUI does not know reads as
/// `query`), the name and the example verbatim, the flow when it is a flow
/// id in the wire form, no path and no node.
pub fn legacy_points(legacy: &LegacyState) -> Vec<InsertionPoint> {
    legacy
        .points
        .iter()
        .enumerate()
        .map(|(k, p)| {
            let (kind, traits) = match p.location.as_str() {
                "body_param" => (InsertionKind::BodyParam, vec![]),
                "header" => (InsertionKind::Header, vec![]),
                "cookie" => (InsertionKind::Cookie, vec![]),
                "path_segment" => (InsertionKind::PathSegment, vec![]),
                "redirect" => (InsertionKind::Query, vec![PointTrait::Url]),
                _ => (InsertionKind::Query, vec![]),
            };
            InsertionPoint {
                id: format!("legacy-{k}"),
                lane: LaneKind::Http,
                kind,
                name: p.name.clone(),
                path: None,
                example: Some(p.example.clone()),
                flow: flow_ref(&p.flow),
                site_node: None,
                traits,
                frequency: 1,
                method: None,
                url: None,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::legacy::InjectionPointRow;

    fn node(id: &str, host: &str, port: u16, scheme: &str) -> SiteNode {
        SiteNode {
            id: id.into(),
            method: "GET".into(),
            scheme: scheme.into(),
            host: host.into(),
            port,
            path_template: format!("/{id}"),
            flows: vec![],
            params: vec![],
            auth: false,
            points: 0,
            audited: false,
        }
    }

    /// Fix round G, G22: the fold sorts the nodes into group order
    /// (`host[:port]` groups in first-appearance order, stable inside a
    /// group, the default port dropped), so `lines` is index for index
    /// with `nodes` and the cursor walks what the pane draws: from `a`,
    /// Down selects `c` (the next row on screen). An appended page keeps
    /// the cursor on the same id.
    #[test]
    fn fold_sorts_nodes_into_group_order_and_the_cursor_follows_the_id() {
        let mut s = SitemapState::default();
        s.fold_result(SitemapResult {
            job: None,
            nodes: vec![
                node("a", "h1", 8080, "http"),
                node("b", "h2", 443, "https"),
                node("c", "h1", 8080, "http"),
                node("d", "h3", 80, "http"),
            ],
            points: vec![],
            next_cursor: None,
        });
        let ids: Vec<&str> = s.nodes.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(ids, vec!["a", "c", "b", "d"]);
        let keys: Vec<&str> = s.lines.iter().map(|l| l.host.as_str()).collect();
        assert_eq!(keys, vec!["h1:8080", "h1:8080", "h2", "h3"]);
        assert_eq!(s.lines[0].text, "GET  /a  flows 0 · pts 0");
        assert_eq!(s.lines.len(), s.nodes.len());
        assert_eq!(s.node_cursor, 0);
        s.node_cursor += 1;
        assert_eq!(s.selected_node().map(|n| n.id.as_str()), Some("c"));

        s.appending = true;
        s.fold_result(SitemapResult {
            job: None,
            nodes: vec![node("e", "h2", 443, "https")],
            points: vec![],
            next_cursor: None,
        });
        let ids: Vec<&str> = s.nodes.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(ids, vec!["a", "c", "b", "e", "d"], "e joins h2's group");
        assert_eq!(
            s.selected_node().map(|n| n.id.as_str()),
            Some("c"),
            "the cursor stays on the same id"
        );
        assert!(node_lines(&[]).is_empty());
    }

    #[test]
    fn point_line_spells_tokens_and_dashes() {
        let p = InsertionPoint {
            id: "p".into(),
            lane: LaneKind::Http,
            kind: InsertionKind::Cookie,
            name: "theme".into(),
            path: None,
            example: None,
            flow: None,
            site_node: None,
            traits: vec![PointTrait::Id, PointTrait::Session],
            frequency: 1,
            method: None,
            url: None,
        };
        assert_eq!(
            point_line(&p),
            "cookie       theme          -                        id,session -"
        );
        assert!(point_header().starts_with("kind         name           path"));
    }

    /// The legacy result reads as one node per URL and one point per row,
    /// so the Site map view draws both sources one way (D12).
    #[test]
    fn legacy_result_reads_as_nodes_and_points() {
        let mut legacy = LegacyState {
            endpoints: vec![
                "http://auth.test/".into(),
                "https://auth.test:8443/login?next=1".into(),
                "auth.test".into(),
            ],
            ..LegacyState::default()
        };
        legacy.endpoint_flows.insert(
            "https://auth.test:8443/login?next=1".into(),
            "550e8400-e29b-41d4-a716-446655440000".into(),
        );
        legacy.points = vec![
            InjectionPointRow {
                flow: "550e8400-e29b-41d4-a716-446655440000".into(),
                location: "redirect".into(),
                name: "next".into(),
                example: "/dashboard".into(),
            },
            InjectionPointRow {
                flow: "f50".into(),
                location: "cookie".into(),
                name: "session".into(),
                example: "<redacted>".into(),
            },
        ];
        let nodes = legacy_nodes(&legacy);
        assert_eq!(nodes.len(), 3);
        assert_eq!(
            (
                nodes[0].scheme.as_str(),
                nodes[0].port,
                nodes[0].path_template.as_str()
            ),
            ("http", 80, "/")
        );
        assert_eq!(nodes[1].host, "auth.test");
        assert_eq!(nodes[1].port, 8443);
        assert_eq!(nodes[1].path_template, "/login?next=1");
        assert_eq!(nodes[1].flows.len(), 1, "a UUID link is a flow");
        assert_eq!(
            nodes[1].points, 1,
            "the redirect point was found in that flow"
        );
        assert_eq!(
            (
                nodes[2].host.as_str(),
                nodes[2].port,
                nodes[2].path_template.as_str()
            ),
            ("auth.test", 80, "/")
        );
        let points = legacy_points(&legacy);
        assert_eq!(points[0].kind, InsertionKind::Query);
        assert_eq!(points[0].traits, vec![PointTrait::Url]);
        assert!(points[0].flow.is_some());
        assert_eq!(points[1].kind, InsertionKind::Cookie);
        assert_eq!(points[1].example.as_deref(), Some("<redacted>"));
        assert!(
            points[1].flow.is_none(),
            "f50 is not a flow id in the wire form"
        );
        assert!(point_line(&points[0]).contains("query"));
    }

    /// The fold sorts points into node order, keeps the orphans last and
    /// clamps the point offset to the selected node's points.
    #[test]
    fn fold_orders_points_by_node_and_clamps_the_offset() {
        let point = |id: &str, node: Option<&str>| InsertionPoint {
            id: id.into(),
            lane: LaneKind::Http,
            kind: InsertionKind::Query,
            name: id.into(),
            path: None,
            example: None,
            flow: None,
            site_node: node.map(str::to_string),
            traits: vec![],
            frequency: 1,
            method: None,
            url: None,
        };
        let mut s = SitemapState::default();
        s.fold_result(SitemapResult {
            job: None,
            nodes: vec![node("a", "h", 80, "http"), node("b", "h", 80, "http")],
            points: vec![
                point("b1", Some("b")),
                point("orphan", None),
                point("a1", Some("a")),
                point("stranger", Some("zzz")),
                point("b2", Some("b")),
            ],
            next_cursor: Some("c".into()),
        });
        let ids: Vec<&str> = s.points.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["a1", "b1", "b2", "orphan", "stranger"],
            "orphans are kept, last, in their order (fix round G, G20)"
        );
        assert_eq!(s.node_points(0), 0..1);
        assert_eq!(s.node_points(1), 1..3);
        assert_eq!(s.node_points(7), 5..5);
        assert_eq!(s.point_offset, 0);
        assert_eq!(s.selected_point().map(|p| p.id.as_str()), Some("a1"));
        assert_eq!(s.summary(), "2 nodes · 1 points of a · n next page");

        // The offset is within the selected node (fix round G, G24): on
        // `b` it names `b1` then `b2`; a fold clamps it to what is left.
        s.node_cursor = 1;
        assert_eq!(s.selected_point().map(|p| p.id.as_str()), Some("b1"));
        s.point_offset = 1;
        assert_eq!(s.selected_point().map(|p| p.id.as_str()), Some("b2"));
        s.point_offset = 9;
        assert_eq!(s.selected_point(), None, "past the node's points");
        s.appending = true;
        s.fold_result(SitemapResult {
            job: None,
            nodes: vec![node("c", "h", 80, "http")],
            points: vec![],
            next_cursor: None,
        });
        assert_eq!(s.nodes.len(), 3, "n appends");
        assert_eq!(
            s.point_offset, 1,
            "the fold clamps the offset to b's last point"
        );
        assert_eq!(s.selected_point().map(|p| p.id.as_str()), Some("b2"));

        // A node without points leaves nothing under the cursor.
        s.node_cursor = 2;
        s.point_offset = 0;
        assert_eq!(s.selected_point(), None);
        assert_eq!(s.summary(), "3 nodes · 0 points of c");
    }

    #[test]
    fn query_args_name_only_what_is_set() {
        let mut q = SitemapQuery::default();
        assert_eq!(q.args(None), json!({}));
        assert!(q.matches("scan-00000000"));
        q.job = Some("scan-1a2b3c4d".into());
        assert_eq!(
            q.args(Some("node-2")),
            json!({ "job": "scan-1a2b3c4d", "cursor": "node-2" })
        );
        assert!(q.matches("scan-1a2b3c4d"));
        assert!(!q.matches("scan-00000000"));
    }
}
