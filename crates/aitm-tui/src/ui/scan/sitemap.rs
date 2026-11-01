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

use aitm_scan_model::InsertionPoint;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use crate::app::App;
use crate::scan::{point_header, point_line, MapPane, MapSource, NodeLine, ScanOffer};
use crate::theme::Theme;
use crate::ui::bars::put;
use crate::ui::scan::{hint, note, pane_rule, panes};
use crate::ui::selection_bg;
use crate::ui::text::{cells, truncate};

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
        map.node_cursor,
        map.pane == MapPane::Nodes,
        Head::Hint(&summary),
        NO_POINTS,
        split.list,
        buf,
    );
    let range = map.node_points(map.node_cursor);
    let cursor = map
        .point_cursor
        .checked_sub(range.start)
        .filter(|c| *c < range.len());
    let header = point_header();
    points(
        theme,
        &map.points[range],
        cursor,
        map.pane == MapPane::Points,
        Head::Columns(&header),
        NO_POINTS,
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
        legacy.endpoint_cursor,
        map.pane == MapPane::Nodes,
        Head::Title(LEGACY_NODES_TITLE),
        LEGACY_NO_ENDPOINTS,
        split.list,
        buf,
    );
    points(
        theme,
        &map.points,
        Some(legacy.cursor),
        map.pane == MapPane::Points,
        Head::Title(LEGACY_POINTS_TITLE),
        LEGACY_NO_POINTS,
        split.detail,
        buf,
    );
}

/// What a pane's first row carries.
enum Head<'a> {
    /// A legacy title, in the accent.
    Title(&'a str),
    /// The v2 summary line, a tertiary [`hint`].
    Hint(&'a str),
    /// The v2 Points column header, in secondary text.
    Columns(&'a str),
}

/// Draw `head` on the first row of `area`.
fn head(theme: &Theme, area: Rect, head: Head<'_>, buf: &mut Buffer) {
    let row = Rect::new(area.x, area.y, area.width, 1);
    let (text, style) = match head {
        Head::Hint(text) => return hint(theme, area, text, buf),
        Head::Title(text) => (text, theme.accent().add_modifier(Modifier::BOLD)),
        Head::Columns(text) => (text, theme.text_secondary()),
    };
    let w = usize::from(area.width).saturating_sub(1);
    put(
        buf,
        row,
        Line::styled(format!(" {}", truncate(text, w)), style),
    );
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
/// node at `cursor` is on screen and highlighted while the pane is focused.
#[allow(clippy::too_many_arguments)]
fn nodes(
    theme: &Theme,
    lines: &[NodeLine],
    cursor: usize,
    focused: bool,
    top_row: Head<'_>,
    empty: &str,
    area: Rect,
    buf: &mut Buffer,
) {
    if area.height == 0 || area.width < 2 {
        return;
    }
    head(theme, area, top_row, buf);
    let body = Rect::new(
        area.x,
        area.y + 1,
        area.width,
        area.height.saturating_sub(1),
    );
    if body.height == 0 {
        return;
    }
    if lines.is_empty() {
        note(theme, body, empty, buf);
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
        .position(|e| matches!(e, Entry::Row(k) if *k == cursor))
        .unwrap_or(0);
    let h = usize::from(body.height);
    let top = cursor_entry.saturating_sub(h - 1);
    let w = usize::from(body.width);
    for (k, entry) in entries.iter().enumerate().skip(top).take(h) {
        let row = Rect::new(body.x, body.y + cells(k - top), body.width, 1);
        match entry {
            Entry::Header(i) => put(
                buf,
                row,
                Line::styled(
                    format!(" {}", truncate(&lines[*i].host, w.saturating_sub(1))),
                    theme.accent(),
                ),
            ),
            Entry::Row(i) => {
                let line = &lines[*i];
                let is_cursor = *i == cursor;
                if is_cursor && focused {
                    buf.set_style(row, selection_bg(theme));
                }
                put(buf, row, marked(theme, &line.text, is_cursor, w));
            }
        }
    }
}

/// The Points pane: the head, then one [`point_line`] per point (built for
/// the rows on screen only), scrolled so `cursor` is on screen and
/// highlighted while the pane is focused; `cursor` is `None` when no point
/// is under it.
#[allow(clippy::too_many_arguments)]
fn points(
    theme: &Theme,
    points: &[InsertionPoint],
    cursor: Option<usize>,
    focused: bool,
    top_row: Head<'_>,
    empty: &str,
    area: Rect,
    buf: &mut Buffer,
) {
    if area.height == 0 || area.width < 2 {
        return;
    }
    head(theme, area, top_row, buf);
    let body = Rect::new(
        area.x,
        area.y + 1,
        area.width,
        area.height.saturating_sub(1),
    );
    if body.height == 0 {
        return;
    }
    if points.is_empty() {
        note(theme, body, empty, buf);
        return;
    }
    let h = usize::from(body.height);
    let top = cursor
        .unwrap_or(0)
        .min(points.len() - 1)
        .saturating_sub(h - 1);
    let w = usize::from(body.width);
    for (k, point) in points.iter().enumerate().skip(top).take(h) {
        let row = Rect::new(body.x, body.y + cells(k - top), body.width, 1);
        let is_cursor = Some(k) == cursor;
        if is_cursor && focused {
            buf.set_style(row, selection_bg(theme));
        }
        put(buf, row, marked(theme, &point_line(point), is_cursor, w));
    }
}

/// `> text` on the cursor row, `  text` elsewhere, cut to `w` cells.
fn marked(theme: &Theme, text: &str, is_cursor: bool, w: usize) -> Line<'static> {
    let mark = if is_cursor { ">" } else { " " };
    let style: Style = theme.text_primary();
    Line::from(vec![
        Span::styled(mark, theme.text_secondary()),
        Span::styled(format!(" {}", truncate(text, w.saturating_sub(2))), style),
    ])
}
