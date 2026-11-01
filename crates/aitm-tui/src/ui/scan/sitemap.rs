//! The Site map tab (spec D2, D11, D12, D13): the nodes grouped under their
//! `host[:port]` headers on the left, the selected node's points on the
//! right, both read from `SitemapState`'s bounded lists (built once per
//! fold, never per frame) and drawn only for the rows on screen.
//!
//! Which cursors the panes follow is `MapSource::from(app.scan_offer())`,
//! never the lists' emptiness: on a v2 bus the `scan.sitemap` cursors, on a
//! legacy bus the `scan.discover` cursors over the same lists, which the
//! `scan.discover` fold set from the legacy result (D12). The two sources
//! differ on screen only in their pane heads: the v2 Nodes pane opens with
//! the summary line (`12 nodes · 2 points of node-1 · n next page`, the
//! list pane's first row as the Issues filter line is; the strip banner
//! carries state) and its Points pane with the column header, the legacy
//! panes keep today's `Endpoints` and `Injection points` titles and list
//! every point (D12: nothing changes in behaviour). The degraded states are
//! the strip banner's (D13: one state on screen).

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};

use crate::app::App;
use crate::scan::{point_header, MapPane, MapSource, NodeLine, ScanOffer};
use crate::text::truncate;
use crate::theme::Theme;
use crate::ui::bars::put;
use crate::ui::scan::{hint, note, pane_rule, panes, rows};

/// Today's legacy pane titles (D12).
const LEGACY_NODES_TITLE: &str = "Endpoints";
const LEGACY_POINTS_TITLE: &str = "Injection points";
/// Today's legacy empty states.
const LEGACY_NO_ENDPOINTS: &str = "none yet: r scans an in-scope target";
const LEGACY_NO_POINTS: &str = "none yet";
/// The v2 Points pane when the selected node has no point.
const NO_POINTS: &str = "no points on this node";

pub fn render(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    let offer = app.scan_offer();
    match offer {
        // The banner carries the no-scanner and missing-verb states; the
        // body adds nothing to them.
        ScanOffer::None => {}
        ScanOffer::V2 if !app.has_tool("scan.sitemap") => {}
        _ => match MapSource::from(offer) {
            MapSource::V2 => v2(app, theme, area, buf),
            MapSource::Legacy => legacy(app, theme, area, buf),
        },
    }
}

/// The v2 map: the summary over the grouped nodes, the selected node's
/// points under the column header.
fn v2(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    let map = &app.scan.sitemap;
    if map.nodes.is_empty() {
        note(theme, area, "no site map yet", buf);
        return;
    }
    let split = panes(area);
    pane_rule(theme, &split, buf);
    let summary = map.summary();
    nodes(
        theme,
        &map.lines,
        Pane {
            cursor: map.node_cursor,
            focused: map.pane == MapPane::Nodes,
            head: Head::Hint(&summary),
            empty: NO_POINTS,
        },
        split.list,
        buf,
    );
    let header = point_header();
    points(
        theme,
        &map.point_lines[map.node_points(map.node_cursor)],
        Pane {
            cursor: map.point_offset,
            focused: map.pane == MapPane::Points,
            head: Head::Columns(&header),
            empty: NO_POINTS,
        },
        split.detail,
        buf,
    );
}

/// The legacy result (D12): the same lists under today's titles, walked
/// by the legacy cursors, every point listed.
fn legacy(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    let map = &app.scan.sitemap;
    let legacy = &app.scan.legacy;
    let split = panes(area);
    pane_rule(theme, &split, buf);
    nodes(
        theme,
        &map.lines,
        Pane {
            cursor: legacy.endpoint_cursor,
            focused: map.pane == MapPane::Nodes,
            head: Head::Title(LEGACY_NODES_TITLE),
            empty: LEGACY_NO_ENDPOINTS,
        },
        split.list,
        buf,
    );
    points(
        theme,
        &map.point_lines,
        Pane {
            cursor: legacy.cursor,
            focused: map.pane == MapPane::Points,
            head: Head::Title(LEGACY_POINTS_TITLE),
            empty: LEGACY_NO_POINTS,
        },
        split.detail,
        buf,
    );
}

/// What a pane's first row carries.
#[derive(Clone, Copy)]
enum Head<'a> {
    /// A legacy title, in the accent.
    Title(&'a str),
    /// The v2 summary line, a tertiary [`hint`].
    Hint(&'a str),
    /// The v2 Points column header, in secondary text.
    Columns(&'a str),
}

/// How one pane is drawn (fix round G, G29): the cursor into its list,
/// whether it is focused, its first row and its empty text.
struct Pane<'a> {
    cursor: usize,
    focused: bool,
    head: Head<'a>,
    empty: &'a str,
}

/// Draw `head` on the first row of `area`.
fn head(theme: &Theme, area: Rect, head: Head<'_>, buf: &mut Buffer) {
    let (text, style) = match head {
        Head::Hint(text) => return hint(theme, area, text, buf),
        Head::Title(text) => (text, theme.accent().add_modifier(Modifier::BOLD)),
        Head::Columns(text) => (text, theme.text_secondary()),
    };
    let row = Rect::new(area.x, area.y, area.width, 1);
    let w = usize::from(area.width).saturating_sub(1);
    put(
        buf,
        row,
        Line::styled(format!(" {}", truncate(text, w)), style),
    );
}

/// The body of a pane under its head: `None` when there is no row for it.
fn body_under_head(theme: &Theme, pane: &Pane<'_>, area: Rect, buf: &mut Buffer) -> Option<Rect> {
    if area.height == 0 || area.width < 2 {
        return None;
    }
    head(theme, area, pane.head, buf);
    let body = Rect::new(
        area.x,
        area.y + 1,
        area.width,
        area.height.saturating_sub(1),
    );
    (body.height > 0).then_some(body)
}

/// One line of the Nodes pane: a host header or a node line.
enum Entry {
    /// The host of the line at this index opens a group.
    Header(usize),
    Row(usize),
}

/// The Nodes pane: the head, then the lines under their host headers (in
/// the accent; `lines` is index for index with the nodes, in group order,
/// so a header opens wherever the key changes), scrolled so the line of the
/// node at the cursor is on screen and highlighted while the pane is
/// focused.
fn nodes(theme: &Theme, lines: &[NodeLine], pane: Pane<'_>, area: Rect, buf: &mut Buffer) {
    let Some(body) = body_under_head(theme, &pane, area, buf) else {
        return;
    };
    if lines.is_empty() {
        note(theme, body, pane.empty, buf);
        return;
    }
    let mut entries: Vec<Entry> = Vec::with_capacity(lines.len() * 2);
    let mut last_host: Option<&str> = None;
    for (k, line) in lines.iter().enumerate() {
        if last_host != Some(line.host.as_str()) {
            entries.push(Entry::Header(k));
            last_host = Some(&line.host);
        }
        entries.push(Entry::Row(k));
    }
    let cursor_entry = entries
        .iter()
        .position(|e| matches!(e, Entry::Row(k) if *k == pane.cursor))
        .unwrap_or(0);
    let w = usize::from(body.width);
    rows(
        theme,
        body,
        entries.len(),
        cursor_entry,
        pane.focused,
        |k| match entries[k] {
            Entry::Header(i) => Line::styled(
                format!(" {}", truncate(&lines[i].host, w.saturating_sub(1))),
                theme.accent(),
            ),
            Entry::Row(i) => marked(theme, &lines[i].text, i == pane.cursor, w),
        },
        buf,
    );
}

/// The Points pane: the head, then one line per point (`points`, the
/// `point_lines` twin the fold built; fix round G, G15), scrolled so the
/// cursor is on screen and highlighted while the pane is focused.
fn points(theme: &Theme, points: &[String], pane: Pane<'_>, area: Rect, buf: &mut Buffer) {
    let Some(body) = body_under_head(theme, &pane, area, buf) else {
        return;
    };
    if points.is_empty() {
        note(theme, body, pane.empty, buf);
        return;
    }
    let w = usize::from(body.width);
    rows(
        theme,
        body,
        points.len(),
        pane.cursor,
        pane.focused,
        |k| marked(theme, &points[k], k == pane.cursor, w),
        buf,
    );
}

/// `> text` on the cursor row, `  text` elsewhere, cut to `w` cells.
fn marked(theme: &Theme, text: &str, is_cursor: bool, w: usize) -> Line<'static> {
    let mark = if is_cursor { ">" } else { " " };
    Line::from(vec![
        Span::styled(mark, theme.text_secondary()),
        Span::styled(
            format!(" {}", truncate(text, w.saturating_sub(2))),
            theme.text_primary(),
        ),
    ])
}
