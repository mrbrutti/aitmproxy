//! Help pages (spec D15, AC-W2-1/2/7; plan task 2, calls C40–C43): the
//! [`HelpPage`] model and [`help_page`], the one renderer behind
//! `aitm --help`, `aitm <group>` and `aitm <group> <verb> --help`.
//!
//! A page is a title, opening paragraphs, bare `Usage:` lines and an ordered
//! list of [`Block`]s (sections of two-column rows, examples, prose, verbatim
//! lines), rendered in that order with one blank line between blocks. Rows put the description
//! at a **fixed column** ([`DESC_COL`], plan C40): a left cell of at most
//! [`LEFT_MAX`] columns is padded so its description starts there, a wider
//! one stands alone and its description starts on the next line. Descriptions
//! wrap greedily to the width with at least twenty columns of room; usage
//! lines wrap in flag-and-placeholder units with a four-space continuation;
//! example lines and verbatim lines are never wrapped (copy-safe, plan C5).
//!
//! The rich form (a stream that animates *and* allows colour, plan C6) paints
//! headings bold and every physical description line dim; everything else is
//! plain, and any other stream gets the same bytes with no escape at all. Every
//! content string is sanitised on the way in; when the caps select ASCII
//! glyphs `·` and `…` become their twins and the title's ` — ` becomes ` - `
//! (spec T1, plan C41). Nothing here touches a terminal or the environment;
//! the caller passes the [`Caps`] it measured for stdout (plan C49).

use std::borrow::Cow;

use crate::caps::Caps;
use crate::card::INDENT;
use crate::glyphs::Glyphs;
use crate::style::{paint, Role};
use crate::text;

/// The 0-based column every description starts at (plan C40).
pub const DESC_COL: usize = 28;
/// The widest left cell that shares its line with the description; a wider
/// one stands alone and the description starts on the next line (C40).
pub const LEFT_MAX: usize = 24;
/// The indent of a usage line's continuation lines (C40).
pub const USAGE_CONT_INDENT: &str = "    ";

/// The least room a description gets however narrow the terminal (C40):
/// `max(width − DESC_COL, MIN_DESC_ROOM)`.
const MIN_DESC_ROOM: usize = 20;
/// The heading over the bare usage lines.
const USAGE_HEADING: &str = "Usage:";
/// The heading over an [`Block::Examples`] block.
const EXAMPLES_HEADING: &str = "Examples:";
/// What every example line starts with (M-W2-1/2/3).
const EXAMPLE_PROMPT: &str = "  $ ";
/// The title's dash and its ASCII form (C41).
const TITLE_DASH: &str = " — ";
const TITLE_DASH_ASCII: &str = " - ";

/// One two-column row: a verb or flag on the left, its description on the
/// right. An empty `left` makes the row an indented paragraph (reserved; no
/// wave-2 page uses it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelpRow {
    pub left: String,
    pub right: String,
}

/// A headed list of rows (`Verbs:`, `Flags:`, `Groups:`, `Options:`, …).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelpSection {
    pub heading: String,
    pub rows: Vec<HelpRow>,
}

/// One block of a page, in the order the page lists them (plan C41): a
/// section of rows, an `Examples:` block of runnable lines, prose paragraphs
/// (a footer such as `Nothing is decrypted until a host is in Scope.`), or
/// lines printed verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    Section(HelpSection),
    Examples(Vec<String>),
    Text(Vec<String>),
    /// Lines printed as they are, one per line, adjacent, with no indent:
    /// never wrapped, never painted, so a two-space gap survives. Sanitised
    /// and ASCII-substituted like every other content string (plan C41; the
    /// top page's footer, M-W2-1).
    Lines(Vec<String>),
}

/// A help page (plan C41), rendered title → about → `Usage:` → blocks.
///
/// `title` is `aitm <group> — <purpose>` on a group page and empty on a verb
/// page (cargo's shape, C43); `about` holds the opening paragraphs; `usage`
/// the bare usage forms (empty on the top page, whose `Usage:` rows carry
/// descriptions and are a section); `blocks` the rest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelpPage {
    pub title: String,
    pub about: Vec<String>,
    pub usage: Vec<String>,
    pub blocks: Vec<Block>,
}

/// One physical line of a row, split where the dim paint goes: the prefix
/// (indent, left cell and padding, or the continuation padding) and the
/// description text on that line, if any.
struct RowLine {
    prefix: String,
    description: Option<String>,
}

/// The lines of one row, unpainted and unsanitised (plan C40).
///
/// With a non-empty `left`, the first line is [`INDENT`], `left` and, when
/// `left` is at most [`LEFT_MAX`] columns wide, padding so the description
/// starts at [`DESC_COL`]; a wider `left` stands alone and every description
/// line follows at [`DESC_COL`]. The description is word-wrapped
/// ([`text::wrap`]) into `max(width − DESC_COL, 20)` columns; continuation
/// lines are padded to [`DESC_COL`]. A row with no description text is its
/// left cell alone, without padding. With an empty `left`, the right text is
/// wrapped to `width` behind [`INDENT`] as plain paragraph lines.
fn row_parts(left: &str, right: &str, width: usize) -> Vec<RowLine> {
    if left.is_empty() {
        return text::wrap(right, width, INDENT)
            .into_iter()
            .map(|line| RowLine {
                prefix: line,
                description: None,
            })
            .collect();
    }
    let room = width.saturating_sub(DESC_COL).max(MIN_DESC_ROOM);
    let mut description = text::wrap(right, room, "").into_iter();
    let left_width = text::width(left);
    let mut lines = Vec::new();
    if left_width <= LEFT_MAX {
        let first = description.next();
        let pad = match first {
            Some(_) => DESC_COL.saturating_sub(INDENT.len() + left_width),
            None => 0,
        };
        lines.push(RowLine {
            prefix: format!("{INDENT}{left}{}", " ".repeat(pad)),
            description: first,
        });
    } else {
        lines.push(RowLine {
            prefix: format!("{INDENT}{left}"),
            description: None,
        });
    }
    lines.extend(description.map(|line| RowLine {
        prefix: " ".repeat(DESC_COL),
        description: Some(line),
    }));
    lines
}

/// The physical lines of one two-column row at `width` columns, unpainted
/// (plan C40; see [`row_parts`] for the layout rules):
///
/// ```text
///   add --host <host>         Add a host, host:port, or *.wildcard to Scope.
///   aitm <group> <verb> [--flag <value>]...
///                             run one command and exit
///   flow                      captured flows: list, inspect, intercept, replay,
///                             edit, export and import
/// ```
pub fn row_lines(left: &str, right: &str, width: usize) -> Vec<String> {
    row_parts(left, right, width)
        .into_iter()
        .map(|line| match line.description {
            Some(description) => format!("{}{description}", line.prefix),
            None => line.prefix,
        })
        .collect()
}

/// A usage line split into units and packed greedily into lines (plan C40).
///
/// A unit is a run of whitespace-separated tokens starting at a token that
/// begins with `--` or `[` (so `--length <length>` and `[--length <length>]`
/// are one unit each, and the leading command words are one unit). Units are
/// packed, single-spaced, into lines of at most `width − 4` columns of
/// content, so a continuation line behind [`USAGE_CONT_INDENT`] ends within
/// the width; the first line is prefixed with [`INDENT`], the rest with
/// [`USAGE_CONT_INDENT`]. A unit wider than the room stands alone, unbroken.
/// A line with no tokens yields no lines.
pub fn wrap_usage(line: &str, width: usize) -> Vec<String> {
    let room = width.saturating_sub(USAGE_CONT_INDENT.len());
    let mut units: Vec<String> = Vec::new();
    for token in line.split_whitespace() {
        let starts_unit = token.starts_with("--") || token.starts_with('[');
        match units.last_mut() {
            Some(unit) if !starts_unit => {
                unit.push(' ');
                unit.push_str(token);
            }
            _ => units.push(token.to_string()),
        }
    }
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut current_width = 0;
    for unit in units {
        let unit_width = text::width(&unit);
        if current.is_empty() {
            current = unit;
            current_width = unit_width;
        } else if current_width + 1 + unit_width <= room {
            current.push(' ');
            current.push_str(&unit);
            current_width += 1 + unit_width;
        } else {
            lines.push(current);
            current = unit;
            current_width = unit_width;
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
        .into_iter()
        .enumerate()
        .map(|(i, content)| {
            let indent = if i == 0 { INDENT } else { USAGE_CONT_INDENT };
            format!("{indent}{content}")
        })
        .collect()
}

/// A content string on its way into the page: sanitised (`text::sanitize`,
/// so a description under an attacker's influence cannot smuggle an escape
/// sequence into the operator's terminal) and, when the caps select ASCII
/// glyphs, with `·` and `…` replaced by the set's `sep` and `ellipsis` (spec
/// T1). Done before layout, so a substituted `...` is measured at its real
/// width.
fn prepare<'a>(caps: &Caps, glyphs: &Glyphs, s: &'a str) -> Cow<'a, str> {
    let s = text::sanitize(s);
    if caps.unicode || !s.contains(['·', '…']) {
        return s;
    }
    Cow::Owned(s.replace('·', glyphs.sep).replace('…', glyphs.ellipsis))
}

/// Renders `page` for `caps` (spec D15, AC-W2-1/2/7).
///
/// Order: the title (when non-empty); each `about` paragraph wrapped to the
/// width with no indent; `Usage:` and each usage line through
/// [`wrap_usage`] (when there is one); then each block — a `Section` as its
/// heading and [`row_lines`] per row, `Examples` as `Examples:` and
/// `  $ <example>` lines printed whole, `Text` as paragraphs wrapped to the
/// width with no indent, `Lines` as its lines verbatim and adjacent — with
/// one blank line between blocks and between `Text` paragraphs. The output ends with exactly one `\n` and has no
/// trailing blank line; a page with nothing to show renders as the empty
/// string.
///
/// Rich (`caps.animate && caps.color`, plan C6): headings are
/// [`Role::Bold`], every physical description line [`Role::Dim`], nothing
/// else is painted. Otherwise no escape byte is written whatever
/// `caps.color` says. Every content string passes [`text::sanitize`] first;
/// when `!caps.unicode`, `·` and `…` follow spec T1's substitution on every
/// line and the title's ` — ` becomes ` - ` (plan C41). Width is
/// `caps.width`.
pub fn help_page(caps: &Caps, page: &HelpPage) -> String {
    let width = usize::from(caps.width);
    let rich = caps.animate && caps.color;
    let glyphs = Glyphs::for_caps(caps);
    let prep = |s: &str| prepare(caps, glyphs, s).into_owned();
    let painted = |role: Role, s: &str| {
        if rich {
            paint(caps, role, s)
        } else {
            s.to_string()
        }
    };

    // Each entry is one block of lines; blank lines go between them.
    let mut blocks: Vec<Vec<String>> = Vec::new();

    if !page.title.is_empty() {
        let mut title = prep(&page.title);
        if !caps.unicode {
            title = title.replace(TITLE_DASH, TITLE_DASH_ASCII);
        }
        blocks.push(vec![title]);
    }
    for paragraph in &page.about {
        blocks.push(text::wrap(&prep(paragraph), width, ""));
    }
    if !page.usage.is_empty() {
        let mut lines = vec![painted(Role::Bold, USAGE_HEADING)];
        for usage in &page.usage {
            lines.extend(wrap_usage(&prep(usage), width));
        }
        blocks.push(lines);
    }
    for block in &page.blocks {
        match block {
            Block::Section(section) => {
                let mut lines = vec![painted(Role::Bold, &prep(&section.heading))];
                for row in &section.rows {
                    let parts = row_parts(&prep(&row.left), &prep(&row.right), width);
                    lines.extend(parts.into_iter().map(|line| match line.description {
                        Some(description) => {
                            format!("{}{}", line.prefix, painted(Role::Dim, &description))
                        }
                        None => line.prefix,
                    }));
                }
                blocks.push(lines);
            }
            Block::Examples(examples) => {
                let mut lines = vec![painted(Role::Bold, EXAMPLES_HEADING)];
                lines.extend(
                    examples
                        .iter()
                        .map(|example| format!("{EXAMPLE_PROMPT}{}", prep(example))),
                );
                blocks.push(lines);
            }
            Block::Text(paragraphs) => {
                for paragraph in paragraphs {
                    blocks.push(text::wrap(&prep(paragraph), width, ""));
                }
            }
            Block::Lines(lines) => {
                blocks.push(lines.iter().map(|line| prep(line)).collect());
            }
        }
    }

    let mut out = String::new();
    for block in blocks.into_iter().filter(|block| !block.is_empty()) {
        if !out.is_empty() {
            out.push('\n');
        }
        for line in block {
            out.push_str(&line);
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caps::Caps;
    use crate::text;

    /// What a UTF-8 pipe gets (plan rule 13).
    fn piped_utf8() -> Caps {
        Caps {
            tty: false,
            color: false,
            unicode: true,
            animate: false,
            width: 80,
            ci: false,
        }
    }

    /// A colour-capable 80-column terminal (plan rule 13).
    fn tty80() -> Caps {
        Caps {
            tty: true,
            color: true,
            unicode: true,
            animate: true,
            width: 80,
            ci: false,
        }
    }

    fn row(left: &str, right: &str) -> HelpRow {
        HelpRow {
            left: left.to_string(),
            right: right.to_string(),
        }
    }

    fn section(heading: &str, rows: Vec<HelpRow>) -> Block {
        Block::Section(HelpSection {
            heading: heading.to_string(),
            rows,
        })
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    /// The `scope.add` description exactly as `aitm-plugins` composes it.
    const SCOPE_ADD_DESCRIPTION: &str = "Add a host, host:port, or *.wildcard to Scope. New connections to it are decrypted from now on; hosts outside Scope are tunnelled. Refused from an agent frontend (MCP) unless scope.allow_agent_widen is set.";

    const FOOTER: &str = "Nothing is decrypted until a host is in Scope.";

    /// The M-W2-2 page, `aitm scope`.
    fn scope_page() -> HelpPage {
        HelpPage {
            title: "aitm scope — which hosts are decrypted".to_string(),
            about: Vec::new(),
            usage: strings(&["aitm scope <verb> [--flag <value>]..."]),
            blocks: vec![
                section(
                    "Verbs:",
                    vec![
                        row(
                            "add --host <host>",
                            "Add a host, host:port, or *.wildcard to Scope.",
                        ),
                        row(
                            "remove --host <host>",
                            "Remove a scope entry (exact match).",
                        ),
                        row("list", "List the current scope entries."),
                    ],
                ),
                Block::Examples(strings(&[
                    "aitm scope add --host app.example.test",
                    "aitm scope add --host '*.example.test'",
                    "aitm scope list",
                ])),
                Block::Text(strings(&[FOOTER])),
            ],
        }
    }

    /// M-W2-2, byte for byte.
    const M_W2_2: &str = "aitm scope — which hosts are decrypted\n\
        \n\
        Usage:\n\
        \x20 aitm scope <verb> [--flag <value>]...\n\
        \n\
        Verbs:\n\
        \x20 add --host <host>         Add a host, host:port, or *.wildcard to Scope.\n\
        \x20 remove --host <host>      Remove a scope entry (exact match).\n\
        \x20 list                      List the current scope entries.\n\
        \n\
        Examples:\n\
        \x20 $ aitm scope add --host app.example.test\n\
        \x20 $ aitm scope add --host '*.example.test'\n\
        \x20 $ aitm scope list\n\
        \n\
        Nothing is decrypted until a host is in Scope.\n";

    /// The M-W2-3 page, `aitm scope add --help`: no title, the description
    /// as the opening paragraph (plan C43).
    fn scope_add_page() -> HelpPage {
        HelpPage {
            title: String::new(),
            about: strings(&[SCOPE_ADD_DESCRIPTION]),
            usage: strings(&["aitm scope add --host <host>"]),
            blocks: vec![
                section(
                    "Flags:",
                    vec![row("--host <string>", "The scope entry to add. [required]")],
                ),
                Block::Examples(strings(&[
                    "aitm scope add --host app.example.test",
                    "aitm scope add --host '*.example.test'",
                ])),
                Block::Text(strings(&[FOOTER])),
            ],
        }
    }

    /// M-W2-3, byte for byte.
    const M_W2_3: &str =
        "Add a host, host:port, or *.wildcard to Scope. New connections to it are\n\
        decrypted from now on; hosts outside Scope are tunnelled. Refused from an agent\n\
        frontend (MCP) unless scope.allow_agent_widen is set.\n\
        \n\
        Usage:\n\
        \x20 aitm scope add --host <host>\n\
        \n\
        Flags:\n\
        \x20 --host <string>           The scope entry to add. [required]\n\
        \n\
        Examples:\n\
        \x20 $ aitm scope add --host app.example.test\n\
        \x20 $ aitm scope add --host '*.example.test'\n\
        \n\
        Nothing is decrypted until a host is in Scope.\n";

    const FLOW_PURPOSE: &str =
        "captured flows: list, inspect, intercept, replay, edit, export and import";

    #[test]
    fn row_that_fits_pads_to_the_description_column() {
        assert_eq!(
            row_lines(
                "add --host <host>",
                "Add a host, host:port, or *.wildcard to Scope.",
                80
            ),
            vec!["  add --host <host>         Add a host, host:port, or *.wildcard to Scope."]
        );
    }

    #[test]
    fn row_too_wide_for_the_left_column_breaks_before_its_description() {
        assert_eq!(
            row_lines(
                "aitm <group> <verb> [--flag <value>]...",
                "run one command and exit",
                80
            ),
            vec![
                "  aitm <group> <verb> [--flag <value>]...",
                "                            run one command and exit",
            ]
        );
    }

    #[test]
    fn row_description_wraps_at_the_description_column() {
        assert_eq!(
            row_lines("flow", FLOW_PURPOSE, 80),
            vec![
                "  flow                      captured flows: list, inspect, intercept, replay,",
                "                            edit, export and import",
            ]
        );
    }

    #[test]
    fn help_page_plain_renders_the_scope_page() {
        let out = help_page(&piped_utf8(), &scope_page());
        assert_eq!(out, M_W2_2);
        assert!(out.ends_with("Nothing is decrypted until a host is in Scope.\n"));
        assert!(!out.ends_with("\n\n"), "no trailing blank line: {out:?}");
        assert!(!out.as_bytes().contains(&0x1b), "{out:?}");
    }

    #[test]
    fn help_page_rich_paints_headings_bold_and_descriptions_dim_only() {
        let rich = help_page(&tty80(), &scope_page());
        let plain = help_page(&piped_utf8(), &scope_page());
        assert!(rich.contains("\x1b[1mUsage:\x1b[0m\n"), "{rich:?}");
        assert!(rich.contains("\x1b[1mVerbs:\x1b[0m\n"), "{rich:?}");
        assert!(rich.contains("\x1b[1mExamples:\x1b[0m\n"), "{rich:?}");
        assert!(
            rich.contains(
                "  list                      \x1b[2mList the current scope entries.\x1b[0m\n"
            ),
            "{rich:?}"
        );
        for line in rich.lines().filter(|l| l.starts_with("  $ ")) {
            assert!(
                !line.as_bytes().contains(&0x1b),
                "an example line is copy-safe: {line:?}"
            );
        }
        // The title, the usage line and the footer stay plain (C41).
        assert!(rich.starts_with("aitm scope — which hosts are decrypted\n\n"));
        assert!(rich.contains("\n  aitm scope <verb> [--flag <value>]...\n"));
        assert!(rich.ends_with("\n\nNothing is decrypted until a host is in Scope.\n"));
        // Exactly three bold headings and three dim descriptions, nothing else.
        assert_eq!(rich.matches("\x1b[1m").count(), 3, "{rich:?}");
        assert_eq!(rich.matches("\x1b[2m").count(), 3, "{rich:?}");
        assert_eq!(rich.matches("\x1b[").count(), 12, "{rich:?}");
        assert_eq!(text::strip_sgr(&rich), plain);
    }

    #[test]
    fn help_page_plain_never_emits_an_escape_even_with_colour_forced() {
        let forced_pipe = Caps {
            tty: false,
            color: true,
            unicode: true,
            animate: false,
            width: 80,
            ci: false,
        };
        let out = help_page(&forced_pipe, &scope_page());
        assert!(!out.as_bytes().contains(&0x1b), "{out:?}");
        assert_eq!(out, M_W2_2);
        // An animating TTY without colour is plain too (C6: both are needed).
        let tty_no_color = Caps {
            color: false,
            ..tty80()
        };
        let out = help_page(&tty_no_color, &scope_page());
        assert!(!out.as_bytes().contains(&0x1b), "{out:?}");
        assert_eq!(out, M_W2_2);
    }

    #[test]
    fn help_page_about_wraps_at_width() {
        let out = help_page(&piped_utf8(), &scope_add_page());
        let mut lines = out.lines();
        assert_eq!(
            lines.next(),
            Some("Add a host, host:port, or *.wildcard to Scope. New connections to it are")
        );
        assert_eq!(
            lines.next(),
            Some("decrypted from now on; hosts outside Scope are tunnelled. Refused from an agent")
        );
        assert_eq!(
            lines.next(),
            Some("frontend (MCP) unless scope.allow_agent_widen is set.")
        );
        assert_eq!(lines.next(), Some(""));
        assert_eq!(out, M_W2_3);
    }

    #[test]
    fn help_page_usage_continuation_indents_four() {
        let page = HelpPage {
            title: String::new(),
            about: Vec::new(),
            usage: strings(&[
                "aitm findings record --title <title> --class <class> --severity <severity> --target <target> --poc_ref <poc_ref>",
            ]),
            blocks: Vec::new(),
        };
        let out = help_page(&piped_utf8(), &page);
        assert_eq!(
            out,
            "Usage:\n  aitm findings record --title <title> --class <class> --severity <severity>\n    --target <target> --poc_ref <poc_ref>\n"
        );
    }

    #[test]
    fn wrap_usage_never_splits_a_flag_from_its_placeholder() {
        assert_eq!(
            wrap_usage(
                "aitm flow detail --id <id> [--body <body>] [--offset <offset>] [--length <length>]",
                80
            ),
            vec![
                "  aitm flow detail --id <id> [--body <body>] [--offset <offset>]",
                "    [--length <length>]",
            ]
        );
        // A line that fits is one indented line.
        assert_eq!(
            wrap_usage("aitm scope add --host <host>", 80),
            vec!["  aitm scope add --host <host>"]
        );
    }

    #[test]
    fn help_page_narrow_width_keeps_twenty_columns_for_descriptions() {
        let narrow = Caps {
            width: 40,
            ..piped_utf8()
        };
        let page = HelpPage {
            title: String::new(),
            about: Vec::new(),
            usage: Vec::new(),
            blocks: vec![section("Groups:", vec![row("flow", FLOW_PURPOSE)])],
        };
        let out = help_page(&narrow, &page);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "Groups:");
        assert_eq!(lines[1], "  flow                      captured flows:");
        assert!(lines.len() > 2, "{out:?}");
        for line in &lines[1..] {
            assert!(text::width(line) <= 48, "{line:?}");
            assert_eq!(line.chars().nth(DESC_COL - 1), Some(' '), "{line:?}");
            assert_ne!(line.chars().nth(DESC_COL), Some(' '), "{line:?}");
            let desc = line.get(DESC_COL..).unwrap_or_default();
            assert!(text::width(desc) <= 20, "{line:?}");
        }
        // Every word of the description is there, in order.
        let joined: Vec<String> = lines[1..]
            .iter()
            .map(|l| l.get(DESC_COL..).unwrap_or_default().to_string())
            .collect();
        assert_eq!(joined.join(" "), FLOW_PURPOSE);
    }

    #[test]
    fn help_page_sanitizes_content() {
        let page = HelpPage {
            title: String::new(),
            about: Vec::new(),
            usage: Vec::new(),
            blocks: vec![section("Verbs:", vec![row("evil", "x\x1b]0;evil\x07y")])],
        };
        let out = help_page(&piped_utf8(), &page);
        assert!(!out.as_bytes().contains(&0x1b), "{out:?}");
        assert!(!out.as_bytes().contains(&0x07), "{out:?}");
        assert!(out.contains('\u{FFFD}'), "{out:?}");
        assert_eq!(
            out,
            "Verbs:\n  evil                      x\u{FFFD}]0;evil\u{FFFD}y\n"
        );
    }

    #[test]
    fn help_page_ascii_substitutes_separator_ellipsis_and_the_title_dash() {
        let page = HelpPage {
            title: "aitm scope — which hosts are decrypted".to_string(),
            about: Vec::new(),
            usage: Vec::new(),
            blocks: vec![Block::Text(strings(&["a · b …"]))],
        };
        let out = help_page(&Caps::plain(), &page);
        assert_eq!(out, "aitm scope - which hosts are decrypted\n\na - b ...\n");
        // A UTF-8 pipe keeps the rich characters.
        assert_eq!(
            help_page(&piped_utf8(), &page),
            "aitm scope — which hosts are decrypted\n\na · b …\n"
        );
    }

    #[test]
    fn help_page_lines_block_is_verbatim_and_unwrapped() {
        let page = HelpPage {
            title: String::new(),
            about: Vec::new(),
            usage: Vec::new(),
            blocks: vec![Block::Lines(strings(&["a  b", "c  d"]))],
        };
        // Two-space gaps kept, the lines adjacent, no indent, at a width that
        // would wrap any paragraph.
        let narrow = Caps {
            width: 10,
            ..piped_utf8()
        };
        assert_eq!(help_page(&narrow, &page), "a  b\nc  d\n");
        // Never painted: the rich form is the same bytes (C41).
        let rich = help_page(&tty80(), &page);
        assert_eq!(rich, "a  b\nc  d\n");
        assert!(!rich.as_bytes().contains(&0x1b), "{rich:?}");
        // Never wrapped: a line wider than the width stays whole (M-W2-1's
        // footer, whose `aitm scope add --host <host>` literal is pinned).
        let footer = HelpPage {
            blocks: vec![Block::Lines(strings(&[
                "Nothing is decrypted until a host is in Scope.  aitm scope add --host <host>",
                "Trust the CA:  aitm ca install",
            ]))],
            ..page.clone()
        };
        assert_eq!(
            help_page(&narrow, &footer),
            "Nothing is decrypted until a host is in Scope.  aitm scope add --host <host>\n\
             Trust the CA:  aitm ca install\n"
        );
        // Sanitised and ASCII-substituted like every other content string.
        let dotted = HelpPage {
            blocks: vec![Block::Lines(strings(&["a · b …", "x\x1b]0;evil\x07y"]))],
            ..page.clone()
        };
        assert_eq!(
            help_page(&Caps::plain(), &dotted),
            "a - b ...\nx\u{FFFD}]0;evil\u{FFFD}y\n"
        );
        assert_eq!(
            help_page(&piped_utf8(), &dotted),
            "a · b …\nx\u{FFFD}]0;evil\u{FFFD}y\n"
        );
        // Among other blocks it is one block: a blank line separates it.
        let between = HelpPage {
            blocks: vec![
                Block::Examples(strings(&["aitm"])),
                Block::Lines(strings(&["a  b", "c  d"])),
            ],
            ..page.clone()
        };
        assert_eq!(
            help_page(&piped_utf8(), &between),
            "Examples:\n  $ aitm\n\na  b\nc  d\n"
        );
    }
}
