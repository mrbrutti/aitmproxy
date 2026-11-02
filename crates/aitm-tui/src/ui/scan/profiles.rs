//! The Profiles tab (spec D2, D8, D11, D13): the profile list on the left
//! ([`list`]), the editor on the right ([`detail`]: the Fields block
//! ([`fields`]), under it the Origins ([`origins`]) or Checks ([`checks`])
//! pane while one is focused, and the shared [`blocked_footer`] with the
//! launch reason over the key footer). The degraded states (a legacy bus,
//! a v2 bus without `scan.profile.list`) are the banner's (D13: one state
//! on screen), so the body draws nothing then.
//!
//! The view draws what the model built and bounded at fold (D6
//! hostile-core bounds: `ProfilesState::lanes_text`/`widest`,
//! `ProfileEditor::tree`, `text_of`), cut to its pane, only for the rows
//! on screen ([`rows`]). Hue only on data (D13): the blocked and refused
//! reasons wear the warning hue, the greyed wildcard rows tertiary text,
//! everything else text tokens; the glyphs are flat monochrome.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use aitm_scan_model::{LaneKind, ProfileListEntry};

use crate::app::App;
use crate::scan::{
    is_wildcard, lane_token, session_line, wire_token, EditorField, ListWidths, NodeKind,
    OriginSource, ProfileEditor, ProfilePane, ProfilesState, ScanOffer, TreeNode, BUILTIN_MARK,
    COLLAPSED_MARK, EDITING_MARK, OPEN_MARK,
};
use crate::text::{cells, fit, truncate, width};
use crate::theme::Theme;
use crate::ui::bars::{put, put_sides};
use crate::ui::scan::hint;
use crate::ui::scan::{
    blocked_footer, key_text, launch_reason, note, pane_rule, panes, rows, stacked, GAP, GAP_TEXT,
    PROFILES_KEYS,
};
use crate::ui::selection_bg;

/// The detail side without an editor.
const NO_EDITOR: &str = "⏎ opens the profile under the cursor · N new profile";
/// The empty state (D13): only when the list is empty and no editor is
/// open, since `N` opens an editor over an empty list.
const NO_PROFILES: &str = "no profiles yet";
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
/// The cells of a list row outside the name and lanes columns: the cursor
/// mark, the held and builtin marks with their pad, three gaps, the
/// intensity and the speed.
const FIXED_W: usize = 1 + 3 + 3 * GAP + INTENSITY_W + SPEED_W;
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
            note(theme, area, NO_PROFILES, buf)
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
    /// (measured once at fold, `ProfilesState::widest`; fix round G, G51)
    /// up to their caps; when the whole row does not fit `avail`, the
    /// lanes column gives way first (down to [`LANES_MIN`]), then the name
    /// (down to [`NAME_MIN`]); past that the row is cut at the right.
    fn measure(widest: ListWidths, avail: usize) -> Self {
        let mut c = Columns {
            name: widest.name.clamp(NAME_MIN, NAME_MAX),
            lanes: widest.lanes.clamp(LANES_MIN, LANES_MAX),
        };
        let over = |c: &Columns| (FIXED_W + c.name + c.lanes).saturating_sub(avail);
        let cut = over(&c).min(c.lanes - LANES_MIN);
        c.lanes -= cut;
        let cut = over(&c).min(c.name - NAME_MIN);
        c.name -= cut;
        c
    }
}

/// The List pane: the column header, then the rows scrolled so the cursor
/// is on screen, the cursor row highlighted while the pane is focused.
fn list(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    if area.height == 0 || area.width < 2 {
        return;
    }
    let profiles = &app.scan.profiles;
    if profiles.list.is_empty() {
        // An editor is open over an empty list (`N`): the list side alone
        // says so.
        note(theme, area, NO_PROFILES, buf);
        return;
    }
    let w = usize::from(area.width);
    let cols = Columns::measure(profiles.widest, w);
    put(
        buf,
        Rect::new(area.x, area.y, area.width, 1),
        clip(
            vec![Span::styled(
                format!(
                    " {}   {GAP_TEXT}{}{GAP_TEXT}{}{GAP_TEXT}{}",
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
    let body = Rect::new(area.x, area.y + 1, area.width, cells(body_h));
    rows(
        theme,
        body,
        profiles.list.len(),
        cursor,
        focused,
        |k| {
            let p = &profiles.list[k];
            let lanes = profiles.lanes_text.get(k).map_or("", String::as_str);
            row_line(
                theme,
                &cols,
                (p, lanes),
                k == cursor,
                held == Some(p.name.as_str()),
                w,
            )
        },
        buf,
    );
}

/// One list row: the cursor mark, the name, the held and builtin marks,
/// the lanes (built at fold), the intensity and the speed. `row` is the
/// list entry and its lanes text, the pair `ProfilesState` keeps side by
/// side (fix round H, H31).
fn row_line(
    theme: &Theme,
    cols: &Columns,
    row: (&ProfileListEntry, &str),
    under_cursor: bool,
    held: bool,
    w: usize,
) -> Line<'static> {
    let (p, lanes) = row;
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
                    "{GAP_TEXT}{}{GAP_TEXT}{}{GAP_TEXT}{}",
                    fit(lanes, cols.lanes),
                    fit(&wire_token(&p.summary.intensity), INTENSITY_W),
                    fit(&wire_token(&p.summary.speed), SPEED_W),
                ),
                theme.text_primary(),
            ),
        ],
        w,
    )
}

/// The detail side: the editor (or the no-editor note) over the shared
/// [`blocked_footer`], which draws the launch reason ([`launch_reason`]:
/// the UI-3 text, D7, else a refused launch's D9 wording, D13) wrapped in
/// the warning hue over the key footer, here where the launch is made.
fn detail(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    if area.height == 0 || area.width < 2 {
        return;
    }
    let reason = launch_reason(app);
    let body = blocked_footer(
        theme,
        area,
        reason.as_deref(),
        &key_text(&[PROFILES_KEYS]),
        buf,
    );
    match app.scan.profiles.editor.as_ref() {
        None => note(theme, body, NO_EDITOR, buf),
        Some(editor) => editor_panes(app, editor, theme, body, buf),
    }
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
            base.patch(selection_bg(theme))
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
        put(
            buf,
            Rect::new(area.x, y, area.width, 1),
            clip(spans, usize::from(area.width)),
        );
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
    // The name is bold as a title; the Fields cursor adds only the
    // selection background on it (`highlight` adds BOLD itself).
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
    // `text_of` is the one text rule the prompt prefill uses too (fix
    // round G, G52): read in place, nothing copied per frame.
    let text = |field: EditorField| editor.text_of(field);
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
            vec![seg(EditorField::Origins, text(EditorField::Origins))],
        ),
        (
            "l4",
            vec![seg(EditorField::L4Targets, text(EditorField::L4Targets))],
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
                seg(EditorField::Intensity, text(EditorField::Intensity)),
                sep("   speed "),
                seg(EditorField::Speed, text(EditorField::Speed)),
                sep("   accuracy "),
                seg(EditorField::Accuracy, text(EditorField::Accuracy)),
            ],
        ),
        (
            "checks",
            vec![seg(
                EditorField::Checks,
                check_summary(profiles, editor, &text(EditorField::Checks)),
            )],
        ),
        (
            "crawl",
            vec![
                seg(EditorField::CrawlStrategy, text(EditorField::CrawlStrategy)),
                sep(" · browser "),
                seg(EditorField::UseBrowser, text(EditorField::UseBrowser)),
                sep(" · depth "),
                seg(EditorField::MaxDepth, text(EditorField::MaxDepth)),
                sep(" · pages "),
                seg(EditorField::MaxPages, text(EditorField::MaxPages)),
                sep(" · forms "),
                seg(EditorField::SubmitForms, text(EditorField::SubmitForms)),
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
                seg(EditorField::OnLost, text(EditorField::OnLost)),
            ],
        ),
        (
            "budget",
            vec![
                sep("probes "),
                seg(EditorField::BudgetProbes, text(EditorField::BudgetProbes)),
                sep(" · time "),
                seg(EditorField::BudgetTimeS, text(EditorField::BudgetTimeS)),
                sep(" s · issues "),
                seg(
                    EditorField::BudgetMaxIssues,
                    text(EditorField::BudgetMaxIssues),
                ),
            ],
        ),
        (
            "http",
            vec![
                sep("version "),
                seg(EditorField::HttpVersion, text(EditorField::HttpVersion)),
                sep(" · record "),
                seg(EditorField::RecordProbes, text(EditorField::RecordProbes)),
            ],
        ),
    ]
}

/// The check summary line (the mockup's `◆ http  ▸ ◆ reflected-xss  ▸ ◇
/// sqli-error`): each lane with its glyph, then its classes after `▸`
/// marks, read from the editor's cached tree (every node, collapse state
/// aside; fix round G, G57), with the include and exclude counts
/// (`counts`, the field's text) after it. Without a catalogue the counts
/// alone.
fn check_summary(profiles: &ProfilesState, editor: &ProfileEditor, counts: &str) -> String {
    if profiles.checks.is_empty() {
        return counts.to_string();
    }
    let mut out = String::new();
    for node in editor.tree.iter().filter(|n| n.kind != NodeKind::Check) {
        if node.kind == NodeKind::Lane {
            if !out.is_empty() {
                out.push_str("  ");
            }
        } else {
            out.push_str(&format!(" {COLLAPSED_MARK} "));
        }
        out.push_str(&format!("{} {}", node.state.glyph(), node.label()));
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
        .filter(|s| is_wildcard(s))
        .collect();
    let choices = &editor.origin_choices;
    if choices.is_empty() && wildcards.is_empty() {
        note(theme, body, NO_ORIGINS, buf);
        return;
    }
    let w = usize::from(body.width);
    // The cursor walks the choices only; the wildcard rows under them are
    // never highlighted (none to walk when there is no choice).
    let focused = app.scan.profiles.pane == ProfilePane::Origins && !choices.is_empty();
    let cursor = editor.origin_cursor.min(choices.len().saturating_sub(1));
    let total = choices.len() + wildcards.len();
    rows(
        theme,
        body,
        total,
        cursor,
        focused,
        |k| {
            if let Some(choice) = choices.get(k) {
                let is_cursor = k == cursor;
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
            }
        },
        buf,
    );
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
    // The visible rows collected once per frame (fix round H, H26).
    let tree: Vec<&TreeNode> = profiles.rows().collect();
    if tree.is_empty() {
        note(theme, body, NO_CHECKS, buf);
        return;
    }
    let w = usize::from(body.width);
    let focused = profiles.pane == ProfilePane::Checks;
    let cursor = editor.tree_cursor.min(tree.len() - 1);
    rows(
        theme,
        body,
        tree.len(),
        cursor,
        focused,
        |k| tree_line(theme, editor, tree[k], k == cursor, w),
        buf,
    );
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
    let fold = if node.kind == NodeKind::Check {
        " "
    } else if editor.collapsed.contains(&node.selector) {
        COLLAPSED_MARK
    } else {
        OPEN_MARK
    };
    let indent = "  ".repeat(usize::from(node.depth));
    clip(
        vec![
            Span::styled(mark.to_string(), theme.accent()),
            Span::styled(format!("{indent}{fold} "), theme.text_secondary()),
            Span::styled(
                format!("{} {}", node.state.glyph(), node.label()),
                theme.text_primary(),
            ),
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

#[cfg(test)]
mod tests {
    use super::*;

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
