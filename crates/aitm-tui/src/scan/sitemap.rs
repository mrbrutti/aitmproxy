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

use std::ops::Range;

use aitm_scan_model::{
    FlowRef, InsertionKind, InsertionPoint, JobId, LaneKind, PointTrait, SiteNode, SitemapResult,
};
use serde::Serialize;
use serde_json::{json, Map, Value};

use super::legacy::LegacyState;
use super::profiles::authority_parts;
use super::{ScanError, ScanOffer};
use crate::text::truncate;

/// How many `Tick`s between two `scan.sitemap` refreshes while the Site map
/// is shown and a job is crawling (spec D6: forty ticks, ten seconds).
pub const SITEMAP_POLL_TICKS: u64 = 40;

/// The most nodes and the most points one `scan.sitemap` page contributes
/// (D6 hostile-core bounds; the Issues page limit, applied to both lists):
/// the rest of a longer page is dropped at fold time.
pub const SITEMAP_PAGE_LIMIT: usize = 512;

/// The mark an audited node's line ends with (D11 `✓`; builder's glyph, flat
/// monochrome as D13 asks).
pub const AUDITED_MARK: &str = "✓";

/// The widest any string of a node or point grows before it is cut, once,
/// at fold time (D6 hostile-core bounds).
const VALUE_MAX: usize = 200;

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
/// header it sits under), its text (`METHOD path_template  flows n · pts n
/// · ✓`) and the index of the node in `SitemapState::nodes` it was built
/// from. Lines are in group order: every line of one host before the next
/// host's, hosts in the order they first appear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeLine {
    pub host: String,
    pub text: String,
    pub node: usize,
}

/// The Site map tab.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SitemapState {
    /// The nodes shown: every `scan.sitemap` page appended so far, or on a
    /// legacy bus the `scan.discover` endpoints read as nodes
    /// ([`SitemapState::show_legacy`], index for index with
    /// `legacy.endpoints`); strings bounded when set.
    pub nodes: Vec<SiteNode>,
    /// The nodes' display twin, one line per node in group order, built
    /// with `nodes` (`lines.len() == nodes.len()`).
    pub lines: Vec<NodeLine>,
    /// The points shown. From `scan.sitemap`: sorted so each node's points
    /// are contiguous in node order ([`SitemapState::node_points`]), a
    /// point naming no node of `nodes` dropped at fold time (the pane lists
    /// the selected node's points, so it has no place to be drawn). On a
    /// legacy bus: the injection points read as points, index for index
    /// with `legacy.points`. Strings bounded when set.
    pub points: Vec<InsertionPoint>,
    /// `Some` while another page can be fetched with `n`.
    pub next_cursor: Option<String>,
    pub node_cursor: usize,
    /// An index into `points`, kept inside the selected node's range by
    /// [`SitemapState::settle_point_cursor`], or `points.len()` when that
    /// node has no points (so nothing is under the cursor).
    pub point_cursor: usize,
    pub pane: MapPane,
    pub query: SitemapQuery,
    /// The tick of the last `scan.sitemap` request.
    pub fetched_at_tick: u64,
    /// The `scan.sitemap` in flight was `n`'s: its reply appends (D10)
    /// instead of replacing. Set when the request leaves, taken by the fold.
    pub appending: bool,
    /// This tab's last error.
    pub error: Option<ScanError>,
}

impl SitemapState {
    /// Fold a `scan.sitemap` reply (spec D10): the page replaces `nodes` and
    /// `points`, or appends to them after `n` (`appending`); `next_cursor`
    /// is the reply's. Hostile-core bounds (D6): the page is cut to
    /// [`SITEMAP_PAGE_LIMIT`] nodes and points, every string is cut to
    /// [`VALUE_MAX`] cells here, once, the lines are rebuilt here, and both
    /// cursors are settled onto what is now listed.
    pub fn fold_result(&mut self, mut result: SitemapResult) {
        let append = std::mem::take(&mut self.appending);
        result.nodes.truncate(SITEMAP_PAGE_LIMIT);
        result.points.truncate(SITEMAP_PAGE_LIMIT);
        result.nodes.iter_mut().for_each(bound_node);
        result.points.iter_mut().for_each(bound_point);
        if append {
            self.nodes.extend(result.nodes);
            self.points.extend(result.points);
        } else {
            self.nodes = result.nodes;
            self.points = result.points;
        }
        self.next_cursor = result.next_cursor;
        self.order_points();
        self.lines = node_lines(&self.nodes);
        debug_assert_eq!(
            self.lines.len(),
            self.nodes.len(),
            "lines is nodes' display twin, one per node"
        );
        self.node_cursor = self.node_cursor.min(self.nodes.len().saturating_sub(1));
        self.settle_point_cursor();
    }

    /// On a legacy bus (D12) the lists are the `scan.discover` result read
    /// as nodes and points ([`legacy_nodes`], [`legacy_points`]), index for
    /// index with `legacy.endpoints` and `legacy.points`, whose cursors the
    /// panes keep walking; bounded and lined like a page, once per result,
    /// so a frame draws bounded text only. The v2 cursors, query and page
    /// cursor are not touched (a legacy bus never has them).
    pub fn show_legacy(&mut self, legacy: &LegacyState) {
        self.nodes = legacy_nodes(legacy);
        self.nodes.iter_mut().for_each(bound_node);
        self.points = legacy_points(legacy);
        self.points.iter_mut().for_each(bound_point);
        self.lines = node_lines(&self.nodes);
    }

    /// Sort `points` into node order (stable, so a node's points keep the
    /// core's order) and drop the ones naming no node of `nodes`.
    fn order_points(&mut self) {
        let position = |p: &InsertionPoint| -> Option<usize> {
            let id = p.site_node.as_deref()?;
            self.nodes.iter().position(|n| n.id == id)
        };
        let mut keyed: Vec<(usize, InsertionPoint)> = std::mem::take(&mut self.points)
            .into_iter()
            .filter_map(|p| position(&p).map(|k| (k, p)))
            .collect();
        keyed.sort_by_key(|(k, _)| *k);
        self.points = keyed.into_iter().map(|(_, p)| p).collect();
    }

    /// The node under the Nodes cursor, if the list has one.
    pub fn selected_node(&self) -> Option<&SiteNode> {
        self.nodes.get(self.node_cursor)
    }

    /// The range of `points` belonging to the node at `idx`: contiguous,
    /// because [`SitemapState::fold_result`] sorts them into node order.
    /// Empty (at the position the node's points would take) when it has
    /// none or `idx` names no node.
    pub fn node_points(&self, idx: usize) -> Range<usize> {
        let Some(node) = self.nodes.get(idx) else {
            return self.points.len()..self.points.len();
        };
        let is_mine = |p: &InsertionPoint| p.site_node.as_deref() == Some(node.id.as_str());
        let Some(start) = self.points.iter().position(is_mine) else {
            return self.points.len()..self.points.len();
        };
        let len = self.points[start..]
            .iter()
            .take_while(|p| is_mine(p))
            .count();
        start..start + len
    }

    /// Keep `point_cursor` on a point of the selected node: inside that
    /// node's range after a walk of the Points pane, on its first point
    /// after a walk of the Nodes pane or a fold, and at `points.len()` (no
    /// point) when the node has none. The shared cursor walk is over the
    /// whole `points` list, so this is what makes `Up`/`Down`/`End` stop at
    /// the node's own points and `Enter` never open another node's flow.
    pub fn settle_point_cursor(&mut self) {
        let range = self.node_points(self.node_cursor);
        self.point_cursor = if range.is_empty() {
            self.points.len()
        } else if self.pane == MapPane::Points && range.contains(&self.point_cursor) {
            self.point_cursor
        } else if self.pane == MapPane::Points && self.point_cursor >= range.end {
            range.end - 1
        } else {
            range.start
        };
    }

    /// The summary line the view draws first (D11: `12 nodes · 2 points of
    /// node-1 · n next page`): the node count, the selected node's point
    /// count and id, and the paging hint only while a next page exists.
    pub fn summary(&self) -> String {
        let mut text = format!("{} nodes", self.nodes.len());
        if let Some(node) = self.selected_node() {
            let n = self.node_points(self.node_cursor).len();
            text.push_str(&format!(" · {n} points of {}", node.id));
        }
        if self.next_cursor.is_some() {
            text.push_str(" · n next page");
        }
        text
    }
}

/// Cut every string the screen reads off a node to [`VALUE_MAX`] cells.
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

/// Cut every string the screen reads off a point to [`VALUE_MAX`] cells.
fn bound_point(point: &mut InsertionPoint) {
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

/// [`truncate`] to [`VALUE_MAX`], skipping the walk when the string is
/// within the cap in bytes (a char is never more cells than bytes).
fn cut(s: &mut String) {
    if s.len() > VALUE_MAX {
        *s = truncate(s, VALUE_MAX);
    }
}

/// The node lines of `nodes` in group order (D11): one line per node under
/// its `host[:port]` key, hosts in first-appearance order, each node's
/// `node` the index it had in `nodes`. The port is shown when it is not the
/// scheme's default (80 for http, 443 for https).
pub fn node_lines(nodes: &[SiteNode]) -> Vec<NodeLine> {
    let mut hosts: Vec<String> = Vec::new();
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for (k, node) in nodes.iter().enumerate() {
        let key = host_key(node);
        match hosts.iter().position(|h| *h == key) {
            Some(g) => groups[g].push(k),
            None => {
                hosts.push(key);
                groups.push(vec![k]);
            }
        }
    }
    hosts
        .into_iter()
        .zip(groups)
        .flat_map(|(host, members)| {
            members.into_iter().map(move |k| NodeLine {
                host: host.clone(),
                text: node_text(&nodes[k]),
                node: k,
            })
        })
        .collect()
}

/// `host[:port]`, the port only when it is not the scheme's default.
fn host_key(node: &SiteNode) -> String {
    let default_port = match node.scheme.as_str() {
        "https" => 443,
        _ => 80,
    };
    if node.port == default_port {
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
        p.traits.iter().map(token).collect::<Vec<_>>().join(",")
    };
    point_columns(
        &token(&p.kind),
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

/// A vocabulary value's wire token (`"json_value"`, `"url"`), read off
/// serde, so the screen spells it as the contract does.
fn token<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "?".to_string())
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
            let (authority, path) = match rest.find(['/', '?', '#']) {
                Some(i) => (&rest[..i], &rest[i..]),
                None => (rest, "/"),
            };
            let (host, port) =
                authority_parts(authority).unwrap_or_else(|_| (authority.to_string(), None));
            let port = port.unwrap_or(if scheme == "https" { 443 } else { 80 });
            let flow = legacy.endpoint_flows.get(url);
            let flows: Vec<FlowRef> = flow
                .and_then(|id| serde_json::from_value(json!(id)).ok())
                .into_iter()
                .collect();
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
                flow: serde_json::from_value(json!(p.flow)).ok(),
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

    /// Lines are grouped by `host[:port]` in first-appearance order, the
    /// default port dropped, each line pointing back at its node.
    #[test]
    fn node_lines_group_by_host_and_keep_the_node_index() {
        let nodes = vec![
            node("a", "h1", 8080, "http"),
            node("b", "h2", 443, "https"),
            node("c", "h1", 8080, "http"),
            node("d", "h3", 80, "http"),
        ];
        let lines = node_lines(&nodes);
        let keys: Vec<(&str, usize)> = lines.iter().map(|l| (l.host.as_str(), l.node)).collect();
        assert_eq!(
            keys,
            vec![("h1:8080", 0), ("h1:8080", 2), ("h2", 1), ("h3", 3)]
        );
        assert_eq!(lines[0].text, "GET  /a  flows 0 · pts 0");
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

    /// The fold sorts points into node order, drops the orphans and settles
    /// the point cursor onto the selected node's range.
    #[test]
    fn fold_orders_points_by_node_and_settles_the_cursor() {
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
        assert_eq!(ids, vec!["a1", "b1", "b2"]);
        assert_eq!(s.node_points(0), 0..1);
        assert_eq!(s.node_points(1), 1..3);
        assert_eq!(s.node_points(7), 3..3);
        assert_eq!(s.point_cursor, 0);
        assert_eq!(s.summary(), "2 nodes · 1 points of a · n next page");

        s.node_cursor = 1;
        s.settle_point_cursor();
        assert_eq!(
            s.point_cursor, 1,
            "the Nodes pane lands on the node's first point"
        );
        s.pane = MapPane::Points;
        s.point_cursor = 0;
        s.settle_point_cursor();
        assert_eq!(s.point_cursor, 1, "Up out of the range stops at its start");
        s.point_cursor = 2;
        s.settle_point_cursor();
        assert_eq!(s.point_cursor, 2, "inside the range it stays");
        s.point_cursor = 9;
        s.settle_point_cursor();
        assert_eq!(s.point_cursor, 2, "past the range it stops at its end");

        // A node without points leaves nothing under the cursor.
        s.appending = true;
        s.fold_result(SitemapResult {
            nodes: vec![node("c", "h", 80, "http")],
            points: vec![],
            next_cursor: None,
        });
        assert_eq!(s.nodes.len(), 3, "n appends");
        s.node_cursor = 2;
        s.settle_point_cursor();
        assert_eq!(s.point_cursor, s.points.len());
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
