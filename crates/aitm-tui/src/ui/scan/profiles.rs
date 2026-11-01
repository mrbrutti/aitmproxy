//! The Profiles tab (spec D2, D8, D11, D13): the profile list on the left,
//! the editor on the right. The degraded states (a legacy bus, a v2 bus
//! without `scan.profile.list`) are the banner's (D13: one state on screen),
//! so the body draws nothing then.
//!
//! Layout (builder's call, from the D11 wide mockup). The List pane: a
//! column header, then one row per profile as `name · lanes · intensity ·
//! speed`, [`BUILTIN_MARK`] after a builtin's name, [`EDITING_MARK`] after
//! the name of the profile the held editor was loaded from (`Esc` returns
//! the pane to the List but keeps the editor; the mark says which row `Tab`
//! returns to), the cursor row marked `>` and highlighted while the List is
//! focused. The detail side: the Fields block (the `profile <name>
//! (builtin)` header with `dirty` right-aligned, then the fields of
//! `EDITOR_FIELDS` in order, grouped onto the mockup's lines, the segment
//! under the Fields cursor highlighted while that pane is focused); under
//! it, only while the Origins or the Checks pane is focused, a rule and
//! that pane (the picker rows with their source, the wildcard scope entries
//! greyed; or the lane to class to check tree with the tri-state glyphs and
//! the collapse markers); at the bottom the `launch.blocked` reason, wrapped
//! and in the warning hue, over the key footer. Without an editor the
//! detail side says how to open one and keeps the footer, since `s` on the
//! List launches the row's profile.
//!
//! Hue only on data (D13): the blocked reason wears the warning hue, the
//! greyed wildcard rows tertiary text, everything else text tokens; the
//! glyphs are flat monochrome. Every string is cut to its pane, and only
//! the rows on screen are built.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use aitm_scan_model::{LaneKind, ProfileListEntry};

use crate::app::App;
use crate::scan::{
    lane_token, session_line, token, tri_state, EditorField, OriginSource, ProfileEditor,
    ProfilePane, ProfilesState, ScanOffer, TreeNode, BUILTIN_MARK, COLLAPSED_MARK, EDITOR_FIELDS,
    OPEN_MARK,
};
use crate::theme::Theme;
use crate::tokens::color::status;
use crate::ui::bars::{put, put_sides};
use crate::ui::scan::{hint, note, pane_rule, panes, stacked};
use crate::ui::selection_bg;
use crate::ui::text::{cells, fit, truncate, width};

/// The mark after the name of the profile the held editor was loaded from
/// (review log, Task 10: `Esc` keeps the editor; the row shows it). The
/// buffer-modified convention; the header's `dirty` says whether it has
/// unsaved changes.
pub const EDITING_MARK: &str = "*";

/// The detail side's footer (D11).
const FOOTER: &str = "s start · m map · w save as · e edit · Space toggle";
/// The detail side without an editor.
const NO_EDITOR: &str = "⏎ opens the profile under the cursor · N new profile";
/// The Origins pane's head: its keys.
const ORIGINS_HEAD: &str = "origins  a add · d remove · o type";
/// The Checks pane's head: its keys.
const CHECKS_HEAD: &str = "checks  Space toggle · h collapse · l expand";
/// What a greyed wildcard scope entry says (D8).
const WILDCARD_HINT: &str = "type an origin (o)";
/// The Origins pane with no choice and no wildcard.
const NO_ORIGINS: &str = "no scope hosts: type an origin (o)";
/// The Checks pane without a catalogue.
const NO_CHECKS: &str = "no check catalogue (scan.checks)";
/// The Fields block's label column (`intensity`, the widest label).
const LABEL_W: usize = 9;
/// The list name column: its header's width to a cap; a longer name is cut.
const NAME_MIN: usize = 4;
const NAME_MAX: usize = 24;
/// The list lanes column: its header's width to `l4_packet l4_stream`.
const LANES_MIN: usize = 5;
const LANES_MAX: usize = 19;
/// The widest intensity word (`intrusive`).
const INTENSITY_W: usize = 9;
/// The widest speed word (`thorough`).
const SPEED_W: usize = 8;
/// Blank cells between list columns.
const GAP: &str = "  ";
const GAP_W: usize = 2;
const _: () = assert!(GAP.len() == GAP_W, "GAP spells GAP_W cells");
/// The cells of a list row outside the name and lanes columns: the cursor
/// mark, the held and builtin marks with their pad, three gaps, the
/// intensity and the speed.
const FIXED_W: usize = 1 + 3 + 3 * GAP_W + INTENSITY_W + SPEED_W;
/// The most rows the blocked reason wraps onto; the rest is cut.
const BLOCKED_ROWS_MAX: usize = 4;
/// The rows the Fields block takes: the header and nine field lines.
const FIELDS_ROWS: u16 = 10;

pub fn render(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    let profiles = &app.scan.profiles;
    match app.scan_offer() {
        // The banner carries the no-scanner, degraded and missing-verb
        // states; the body adds nothing to them.
        ScanOffer::None | ScanOffer::Legacy => {}
        ScanOffer::V2 if !app.has_tool("scan.profile.list") => {}
        ScanOffer::V2 if profiles.list.is_empty() && profiles.editor.is_none() => {
            note(theme, area, "no profiles yet", buf)
        }
        ScanOffer::V2 => {
            if area.height == 0 || area.width == 0 {
                return;
            }
            let split = panes(area);
            pane_rule(theme, &split, buf);
            list(app, theme, split.list, buf);
            detail(app, theme, split.detail, buf);
        }
    }
}

/// The measured list columns.
struct Columns {
    name: usize,
    lanes: usize,
}

impl Columns {
    /// Measure the rows: the name and lanes columns their widest content
    /// up to their caps; when the whole row does not fit `avail`, the
    /// lanes column gives way first (down to [`LANES_MIN`]), then the name
    /// (down to [`NAME_MIN`]); past that the row is cut at the right.
    fn measure(list: &[ProfileListEntry], avail: usize) -> Self {
        let mut c = Columns {
            name: list
                .iter()
                .map(|p| width(&p.name))
                .max()
                .unwrap_or(0)
                .clamp(NAME_MIN, NAME_MAX),
            lanes: list
                .iter()
                .map(|p| width(&lanes_text(&p.summary.lanes)))
                .max()
                .unwrap_or(0)
                .clamp(LANES_MIN, LANES_MAX),
        };
        let over = |c: &Columns| (FIXED_W + c.name + c.lanes).saturating_sub(avail);
        let cut = over(&c).min(c.lanes - LANES_MIN);
        c.lanes -= cut;
        let cut = over(&c).min(c.name - NAME_MIN);
        c.name -= cut;
        c
    }
}

/// `http ws`, the lanes in their wire tokens.
fn lanes_text(lanes: &[LaneKind]) -> String {
    lanes
        .iter()
        .map(|l| lane_token(*l))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The List pane: the column header, then the rows scrolled so the cursor
/// is on screen, the cursor row highlighted while the pane is focused.
fn list(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    if area.height == 0 || area.width < 2 {
        return;
    }
    let profiles = &app.scan.profiles;
    if profiles.list.is_empty() {
        note(theme, area, "no profiles yet", buf);
        return;
    }
    let w = usize::from(area.width);
    let cols = Columns::measure(&profiles.list, w);
    put(
        buf,
        Rect::new(area.x, area.y, area.width, 1),
        clip(
            vec![Span::styled(
                format!(
                    " {}   {GAP}{}{GAP}{}{GAP}{}",
                    fit("name", cols.name),
                    fit("lanes", cols.lanes),
                    fit("intensity", INTENSITY_W),
                    "speed"
                ),
                theme.text_secondary(),
            )],
            w,
        ),
    );
    let body_h = usize::from(area.height.saturating_sub(1));
    if body_h == 0 {
        return;
    }
    let cursor = profiles.cursor.min(profiles.list.len() - 1);
    let focused = profiles.pane == ProfilePane::List;
    let held = profiles
        .editor
        .as_ref()
        .and_then(|e| e.loaded_from.as_deref());
    let top = cursor.saturating_sub(body_h - 1);
    for (k, p) in profiles.list.iter().enumerate().skip(top).take(body_h) {
        let row = Rect::new(area.x, area.y + 1 + cells(k - top), area.width, 1);
        if k == cursor && focused {
            buf.set_style(row, selection_bg(theme));
        }
        put(
            buf,
            row,
            row_line(
                theme,
                &cols,
                p,
                k == cursor,
                held == Some(p.name.as_str()),
                w,
            ),
        );
    }
}

/// One list row: the cursor mark, the name, the held and builtin marks,
/// the lanes, the intensity and the speed.
fn row_line(
    theme: &Theme,
    cols: &Columns,
    p: &ProfileListEntry,
    under_cursor: bool,
    held: bool,
    w: usize,
) -> Line<'static> {
    let mark = if under_cursor { ">" } else { " " };
    let editing = if held { EDITING_MARK } else { " " };
    let builtin = if p.builtin { BUILTIN_MARK } else { " " };
    clip(
        vec![
            Span::styled(mark.to_string(), theme.accent()),
            Span::styled(fit(&p.name, cols.name), theme.text_primary()),
            Span::styled(format!(" {editing}{builtin}"), theme.text_secondary()),
            Span::styled(
                format!(
                    "{GAP}{}{GAP}{}{GAP}{}",
                    fit(&lanes_text(&p.summary.lanes), cols.lanes),
                    fit(&token(&p.summary.intensity), INTENSITY_W),
                    fit(&token(&p.summary.speed), SPEED_W),
                ),
                theme.text_primary(),
            ),
        ],
        w,
    )
}

/// The detail side: the editor (or the no-editor note) over the blocked
/// reason and the footer. The footer takes the last row when there are two
/// or more; the blocked reason the rows above it, wrapped, leaving at least
/// one row to the body.
fn detail(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    if area.height == 0 || area.width < 2 {
        return;
    }
    let w = usize::from(area.width) - 1;
    let blocked = app
        .scan
        .launch
        .blocked
        .as_deref()
        .map(|text| wrap(text, w, BLOCKED_ROWS_MAX))
        .unwrap_or_default();
    let h = usize::from(area.height);
    let foot_rows = if h >= 2 {
        (1 + blocked.len()).min(h - 1)
    } else {
        0
    };
    let body = Rect::new(area.x, area.y, area.width, cells(h - foot_rows));
    match app.scan.profiles.editor.as_ref() {
        None => note(theme, body, NO_EDITOR, buf),
        Some(editor) => editor_panes(app, editor, theme, body, buf),
    }
    if foot_rows == 0 {
        return;
    }
    let foot_y = area.y + cells(h - foot_rows);
    // The reason's rows that fit over the footer, in the warning hue
    // (D13's refused state; `status.clientError` is the `state.warning`
    // foreground on both schemes).
    let warn = theme.fg(&status::CLIENT_ERROR);
    for (k, row) in blocked.iter().take(foot_rows - 1).enumerate() {
        put(
            buf,
            Rect::new(area.x, foot_y + cells(k), area.width, 1),
            Line::styled(format!(" {row}"), warn),
        );
    }
    hint(
        theme,
        Rect::new(area.x, area.bottom() - 1, area.width, 1),
        FOOTER,
        buf,
    );
}

/// The Fields block, and under it the Origins or the Checks pane while
/// one of them is focused ([`stacked`] with the block's rows on top).
fn editor_panes(app: &App, editor: &ProfileEditor, theme: &Theme, area: Rect, buf: &mut Buffer) {
    let profiles = &app.scan.profiles;
    match profiles.pane {
        ProfilePane::List | ProfilePane::Fields => fields(profiles, editor, theme, area, buf),
        ProfilePane::Origins | ProfilePane::Checks => {
            let split = stacked(area, FIELDS_ROWS);
            pane_rule(theme, &split, buf);
            fields(profiles, editor, theme, split.list, buf);
            if profiles.pane == ProfilePane::Origins {
                origins(app, editor, theme, split.detail, buf);
            } else {
                checks(profiles, editor, theme, split.detail, buf);
            }
        }
    }
}

/// One run of a Fields line: the field it edits (highlighted under the
/// cursor) or a connective.
struct Seg {
    field: Option<EditorField>,
    text: String,
}

fn seg(field: EditorField, text: impl Into<String>) -> Seg {
    Seg {
        field: Some(field),
        text: text.into(),
    }
}

fn sep(text: &str) -> Seg {
    Seg {
        field: None,
        text: text.to_string(),
    }
}

/// The Fields block: the header, then the field lines of the D11 mockup
/// in `EDITOR_FIELDS` order, scrolled so the cursor's line is on screen,
/// the cursor's segment highlighted while the pane is focused.
fn fields(
    profiles: &ProfilesState,
    editor: &ProfileEditor,
    theme: &Theme,
    area: Rect,
    buf: &mut Buffer,
) {
    if area.height == 0 || area.width < 2 {
        return;
    }
    let w = usize::from(area.width) - 1;
    let focused = profiles.pane == ProfilePane::Fields;
    let cursor = editor.field();
    let lines = field_lines(profiles, editor);
    // The header is line 0; the cursor's line is the first carrying its
    // field.
    let cursor_line = lines
        .iter()
        .position(|(_, segs)| segs.iter().any(|s| s.field == Some(cursor)))
        .map_or(0, |i| i + 1);
    let h = usize::from(area.height);
    let top = cursor_line.saturating_sub(h - 1);
    let highlight = |field: Option<EditorField>, base: Style| -> Style {
        if focused && field == Some(cursor) {
            base.patch(selection_bg(theme)).add_modifier(Modifier::BOLD)
        } else {
            base
        }
    };
    let mut y = area.y;
    if top == 0 {
        header(
            editor,
            theme,
            highlight(Some(EditorField::Name), theme.text_primary()),
            area,
            buf,
        );
        y += 1;
    }
    let shown = h - usize::from(top == 0);
    for (label, segs) in lines.iter().skip(top.saturating_sub(1)).take(shown) {
        let mut spans = Vec::with_capacity(segs.len() + 1);
        if label.is_empty() {
            spans.push(Span::raw(" "));
        } else {
            spans.push(Span::styled(
                format!(" {} ", fit(label, LABEL_W)),
                theme.text_secondary(),
            ));
        }
        for s in segs {
            let base = if s.field.is_some() {
                theme.text_primary()
            } else {
                theme.text_secondary()
            };
            spans.push(Span::styled(s.text.clone(), highlight(s.field, base)));
        }
        put(buf, Rect::new(area.x, y, area.width, 1), clip(spans, w + 1));
        y += 1;
    }
}

/// `profile <name> (builtin)`, `dirty` right-aligned (the mockup's header).
fn header(editor: &ProfileEditor, theme: &Theme, name_style: Style, area: Rect, buf: &mut Buffer) {
    let w = usize::from(area.width).saturating_sub(1);
    let name = if editor.draft.name.is_empty() {
        "(unnamed)".to_string()
    } else {
        editor.draft.name.clone()
    };
    let mut left = vec![
        Span::styled(" profile ".to_string(), theme.text_secondary()),
        Span::styled(name, name_style.add_modifier(Modifier::BOLD)),
    ];
    if editor.builtin {
        left.push(Span::styled(" (builtin)", theme.text_secondary()));
    }
    let right = if editor.dirty {
        Line::styled("dirty", theme.text_secondary())
    } else {
        Line::default()
    };
    put_sides(
        buf,
        Rect::new(area.x, area.y, area.width, 1),
        clip(left, w),
        right,
    );
}

/// The field lines after the header, each a label and its segments, in
/// `EDITOR_FIELDS` order: origins; l4 targets; the four lanes; intensity,
/// speed, accuracy; the check summary; the crawl dials; the session line
/// (verbatim, names only) and `on_lost`; the budget; the http dials.
fn field_lines(profiles: &ProfilesState, editor: &ProfileEditor) -> Vec<(&'static str, Vec<Seg>)> {
    // One clone per frame: `field_text` reads the field under the cursor,
    // so the probe walks the fields for the one text rule the prompt uses.
    let mut probe = editor.clone();
    let text = |probe: &mut ProfileEditor, field: EditorField| -> String {
        probe.field = EDITOR_FIELDS
            .iter()
            .position(|f| *f == field)
            .unwrap_or_default();
        probe.field_text()
    };
    let d = &editor.draft;
    let lane = |field: EditorField, kind: LaneKind| -> Seg {
        let on = if d.lanes.contains(&kind) {
            "[x]"
        } else {
            "[ ]"
        };
        seg(field, format!("{on} {}", lane_token(kind)))
    };
    vec![
        (
            "origins",
            vec![seg(
                EditorField::Origins,
                text(&mut probe, EditorField::Origins),
            )],
        ),
        (
            "l4",
            vec![seg(
                EditorField::L4Targets,
                text(&mut probe, EditorField::L4Targets),
            )],
        ),
        (
            "lanes",
            vec![
                lane(EditorField::LaneHttp, LaneKind::Http),
                sep("  "),
                lane(EditorField::LaneWs, LaneKind::Ws),
                sep("  "),
                lane(EditorField::LaneL4Packet, LaneKind::L4Packet),
                sep("  "),
                lane(EditorField::LaneL4Stream, LaneKind::L4Stream),
            ],
        ),
        (
            "intensity",
            vec![
                seg(
                    EditorField::Intensity,
                    text(&mut probe, EditorField::Intensity),
                ),
                sep("   speed "),
                seg(EditorField::Speed, text(&mut probe, EditorField::Speed)),
                sep("   accuracy "),
                seg(
                    EditorField::Accuracy,
                    text(&mut probe, EditorField::Accuracy),
                ),
            ],
        ),
        (
            "checks",
            vec![seg(
                EditorField::Checks,
                check_summary(profiles, editor, &text(&mut probe, EditorField::Checks)),
            )],
        ),
        (
            "crawl",
            vec![
                seg(
                    EditorField::CrawlStrategy,
                    text(&mut probe, EditorField::CrawlStrategy),
                ),
                sep(" · browser "),
                seg(
                    EditorField::UseBrowser,
                    text(&mut probe, EditorField::UseBrowser),
                ),
                sep(" · depth "),
                seg(
                    EditorField::MaxDepth,
                    text(&mut probe, EditorField::MaxDepth),
                ),
                sep(" · pages "),
                seg(
                    EditorField::MaxPages,
                    text(&mut probe, EditorField::MaxPages),
                ),
                sep(" · forms "),
                seg(
                    EditorField::SubmitForms,
                    text(&mut probe, EditorField::SubmitForms),
                ),
            ],
        ),
        (
            "",
            vec![
                seg(
                    EditorField::SessionMode,
                    session_line(editor, &profiles.previews),
                ),
                sep(" · on_lost "),
                seg(EditorField::OnLost, text(&mut probe, EditorField::OnLost)),
            ],
        ),
        (
            "budget",
            vec![
                sep("probes "),
                seg(
                    EditorField::BudgetProbes,
                    text(&mut probe, EditorField::BudgetProbes),
                ),
                sep(" · time "),
                seg(
                    EditorField::BudgetTimeS,
                    text(&mut probe, EditorField::BudgetTimeS),
                ),
                sep(" s · issues "),
                seg(
                    EditorField::BudgetMaxIssues,
                    text(&mut probe, EditorField::BudgetMaxIssues),
                ),
            ],
        ),
        (
            "http",
            vec![
                sep("version "),
                seg(
                    EditorField::HttpVersion,
                    text(&mut probe, EditorField::HttpVersion),
                ),
                sep(" · record "),
                seg(
                    EditorField::RecordProbes,
                    text(&mut probe, EditorField::RecordProbes),
                ),
            ],
        ),
    ]
}

/// The check summary line (the mockup's `◆ http  ▸ ◆ reflected-xss  ▸ ○
/// sqli-error`): each lane with its glyph, then its classes after `▸`
/// marks, read from the full tree (collapse state aside), with the
/// include and exclude counts (`counts`, the field's text) after it.
/// Without a catalogue the counts alone.
fn check_summary(profiles: &ProfilesState, editor: &ProfileEditor, counts: &str) -> String {
    if profiles.checks.is_empty() {
        return counts.to_string();
    }
    let tree = crate::scan::check_tree(&profiles.checks, &Default::default());
    let mut out = String::new();
    for node in tree.iter().filter(|n| n.depth < 2) {
        let glyph = tri_state(&editor.draft.checks, &node.selector).glyph();
        if node.depth == 0 {
            if !out.is_empty() {
                out.push_str("  ");
            }
        } else {
            out.push_str(&format!(" {COLLAPSED_MARK} "));
        }
        out.push_str(&format!("{glyph} {}", node.label));
    }
    format!("{out} · {counts}")
}

/// The Origins pane (D8): the head, then the picker rows as `[x] origin
/// source` (ticked when the origin is in the draft), the cursor row marked
/// and highlighted while the pane is focused, then the wildcard scope
/// entries greyed with the hint to type one.
fn origins(app: &App, editor: &ProfileEditor, theme: &Theme, area: Rect, buf: &mut Buffer) {
    if area.height == 0 || area.width < 2 {
        return;
    }
    hint(theme, area, ORIGINS_HEAD, buf);
    let body = Rect::new(
        area.x,
        area.y + 1,
        area.width,
        area.height.saturating_sub(1),
    );
    if body.height == 0 {
        return;
    }
    let wildcards: Vec<&str> = app
        .scope
        .iter()
        .map(String::as_str)
        .filter(|s| s.starts_with("*."))
        .collect();
    let choices = &editor.origin_choices;
    if choices.is_empty() && wildcards.is_empty() {
        note(theme, body, NO_ORIGINS, buf);
        return;
    }
    let h = usize::from(body.height);
    let w = usize::from(body.width);
    let focused = app.scan.profiles.pane == ProfilePane::Origins;
    let cursor = editor.origin_cursor.min(choices.len().saturating_sub(1));
    let total = choices.len() + wildcards.len();
    let top = cursor.saturating_sub(h - 1);
    for k in top..total.min(top + h) {
        let row = Rect::new(body.x, body.y + cells(k - top), body.width, 1);
        let line = if let Some(choice) = choices.get(k) {
            let is_cursor = k == cursor;
            if is_cursor && focused {
                buf.set_style(row, selection_bg(theme));
            }
            let mark = if is_cursor { ">" } else { " " };
            let tick = if editor.draft.target.origins.contains(&choice.origin) {
                "[x]"
            } else {
                "[ ]"
            };
            let source = match choice.source {
                OriginSource::FromScope => "scope",
                OriginSource::FromFlows => "flows",
                OriginSource::Typed => "typed",
            };
            clip(
                vec![
                    Span::styled(mark.to_string(), theme.accent()),
                    Span::styled(format!("{tick} {}", choice.origin), theme.text_primary()),
                    Span::styled(format!("  {source}"), theme.text_secondary()),
                ],
                w,
            )
        } else {
            let entry = wildcards[k - choices.len()];
            clip(
                vec![Span::styled(
                    format!("     {entry}  {WILDCARD_HINT}"),
                    theme.text_tertiary(),
                )],
                w,
            )
        };
        put(buf, row, line);
    }
}

/// The Checks pane (D11): the head, then the flattened tree, one row per
/// node as `<collapse mark> <tri-state glyph> <label>` indented by depth,
/// scrolled so the cursor is on screen and highlighted while the pane is
/// focused.
fn checks(
    profiles: &ProfilesState,
    editor: &ProfileEditor,
    theme: &Theme,
    area: Rect,
    buf: &mut Buffer,
) {
    if area.height == 0 || area.width < 2 {
        return;
    }
    hint(theme, area, CHECKS_HEAD, buf);
    let body = Rect::new(
        area.x,
        area.y + 1,
        area.width,
        area.height.saturating_sub(1),
    );
    if body.height == 0 {
        return;
    }
    let tree = profiles.tree();
    if tree.is_empty() {
        note(theme, body, NO_CHECKS, buf);
        return;
    }
    let h = usize::from(body.height);
    let w = usize::from(body.width);
    let focused = profiles.pane == ProfilePane::Checks;
    let cursor = editor.tree_cursor.min(tree.len() - 1);
    let top = cursor.saturating_sub(h - 1);
    for (k, node) in tree.iter().enumerate().skip(top).take(h) {
        let row = Rect::new(body.x, body.y + cells(k - top), body.width, 1);
        let is_cursor = k == cursor;
        if is_cursor && focused {
            buf.set_style(row, selection_bg(theme));
        }
        put(buf, row, tree_line(theme, editor, node, is_cursor, w));
    }
}

/// One tree row.
fn tree_line(
    theme: &Theme,
    editor: &ProfileEditor,
    node: &TreeNode,
    under_cursor: bool,
    w: usize,
) -> Line<'static> {
    let mark = if under_cursor { ">" } else { " " };
    let fold = if node.depth >= 2 {
        " "
    } else if editor.collapsed.contains(&node.selector) {
        COLLAPSED_MARK
    } else {
        OPEN_MARK
    };
    let glyph = tri_state(&editor.draft.checks, &node.selector).glyph();
    let indent = "  ".repeat(usize::from(node.depth));
    clip(
        vec![
            Span::styled(mark.to_string(), theme.accent()),
            Span::styled(format!("{indent}{fold} "), theme.text_secondary()),
            Span::styled(format!("{glyph} {}", node.label), theme.text_primary()),
        ],
        w,
    )
}

/// Cut `spans` to `w` cells: the spans that fit whole are kept, the one
/// that crosses the limit is cut with an ellipsis, the rest dropped.
fn clip(spans: Vec<Span<'static>>, w: usize) -> Line<'static> {
    let mut used = 0;
    let mut out = Vec::with_capacity(spans.len());
    for span in spans {
        let span_w = width(&span.content);
        if used + span_w <= w {
            used += span_w;
            out.push(span);
            continue;
        }
        let room = w.saturating_sub(used);
        if room > 0 {
            out.push(Span::styled(truncate(&span.content, room), span.style));
        }
        break;
    }
    Line::from(out)
}

/// Wrap `text` into rows of at most `w` cells, at most `max_rows` of them.
/// The units are the text's clauses (cut after a `,` `.` `:` or `;` that a
/// space follows, so a dotted address stays whole), and the words of a
/// clause wider than a row: the D7 reasons name the missing scope entry
/// clause by clause (`direction outbound,`), and a clause kept on one row
/// keeps each `field value` pair readable. A word wider than a row is cut,
/// and when the units do not all fit the rows the last row ends in an
/// ellipsis.
fn wrap(text: &str, w: usize, max_rows: usize) -> Vec<String> {
    if w == 0 || max_rows == 0 {
        return Vec::new();
    }
    let mut units: Vec<&str> = Vec::new();
    for clause in clauses(text) {
        if width(clause) <= w {
            units.push(clause);
        } else {
            units.extend(clause.split_whitespace());
        }
    }
    let mut rows: Vec<String> = Vec::new();
    let mut i = 0;
    while i < units.len() && rows.len() < max_rows {
        let mut row = String::new();
        while i < units.len() {
            let unit = units[i];
            if row.is_empty() {
                row = truncate(unit, w);
            } else if width(&row) + 1 + width(unit) <= w {
                row.push(' ');
                row.push_str(unit);
            } else {
                break;
            }
            i += 1;
        }
        rows.push(row);
    }
    if i < units.len() {
        if let Some(last) = rows.last_mut() {
            *last = truncate(&format!("{last} …"), w);
        }
    }
    rows
}

/// `text` cut after every `,` `.` `:` or `;` that whitespace or the end
/// follows, each piece trimmed, empty pieces dropped.
fn clauses(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    for (i, b) in bytes.iter().enumerate() {
        let ends_clause = matches!(b, b',' | b'.' | b':' | b';')
            && bytes.get(i + 1).is_none_or(u8::is_ascii_whitespace);
        if ends_clause {
            // `b` is ASCII, so `i + 1` is a char boundary.
            let clause = text[start..=i].trim();
            if !clause.is_empty() {
                out.push(clause);
            }
            start = i + 1;
        }
    }
    let tail = text[start..].trim();
    if !tail.is_empty() {
        out.push(tail);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wrap keeps words whole, cuts a word wider than a row, stops at
    /// the row cap and marks what it dropped.
    #[test]
    fn wrap_breaks_at_clauses_then_spaces_and_caps_the_rows() {
        assert_eq!(wrap("a bb ccc", 5, 4), vec!["a bb", "ccc"]);
        assert_eq!(wrap("abcdefgh ij", 5, 4), vec!["abcd…", "ij"]);
        assert_eq!(wrap("one two three four", 9, 1), vec!["one two …"]);
        assert_eq!(wrap("one two", 9, 1), vec!["one two"]);
        assert!(wrap("x", 0, 4).is_empty());
        assert!(wrap("", 9, 4).is_empty());
        // A clause that fits moves whole to the next row; a dotted address
        // is not a clause end.
        assert_eq!(
            wrap("Add one with x, direction outbound, 10.0.0.1/32 y.", 22, 4),
            vec!["Add one with x,", "direction outbound,", "10.0.0.1/32 y."]
        );
        assert_eq!(clauses("a: b, c.d; e"), vec!["a:", "b,", "c.d;", "e"]);
    }

    /// The clip keeps whole spans, cuts the crossing one with an ellipsis
    /// and drops the rest.
    #[test]
    fn clip_cuts_the_crossing_span() {
        let text =
            |l: Line<'static>| -> String { l.spans.iter().map(|s| s.content.as_ref()).collect() };
        let spans = || vec![Span::raw("abc"), Span::raw("defg"), Span::raw("hij")];
        assert_eq!(text(clip(spans(), 20)), "abcdefghij");
        assert_eq!(text(clip(spans(), 5)), "abcd…");
        assert_eq!(text(clip(spans(), 3)), "abc");
        assert_eq!(text(clip(spans(), 0)), "");
    }
}
