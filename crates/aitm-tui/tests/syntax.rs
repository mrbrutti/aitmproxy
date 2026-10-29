//! Task 7 (TUI, UI-ext plan): the Rhai and PoC-YAML tokenizers colour the two
//! languages an operator edits by the foundation `syntax.*` tokens, and stay
//! tolerant of partial/odd input — a bad line still renders and later lines
//! keep their colour (plan Review Focus: "malformed / partial source while
//! typing"). Driven by the shared grammar in `docs/design/languages/`.

use aitm_tui::syntax::{self, SyntaxToken};
use aitm_tui::theme::Theme;

fn flat(lines: &[Vec<(SyntaxToken, String)>]) -> Vec<(SyntaxToken, String)> {
    lines.iter().flatten().cloned().collect()
}

fn has(toks: &[(SyntaxToken, String)], k: SyntaxToken, text: &str) -> bool {
    toks.iter().any(|(tk, t)| *tk == k && t == text)
}

#[test]
fn rhai_colours_keyword_string_number_comment() {
    let src = "fn on_request(flow) { let x = \"a\"; let n = 42; } // c";
    let toks = flat(&syntax::rhai::tokenize(src));
    assert!(has(&toks, SyntaxToken::Keyword, "fn"));
    assert!(has(&toks, SyntaxToken::Keyword, "let"));
    assert!(has(&toks, SyntaxToken::Str, "\"a\""));
    assert!(has(&toks, SyntaxToken::Number, "42"));
    assert!(toks
        .iter()
        .any(|(k, t)| *k == SyntaxToken::Comment && t.contains("// c")));
    // identifiers are plain text, not keywords
    assert!(has(&toks, SyntaxToken::Text, "flow"));
}

#[test]
fn rhai_colours_boolean_literals() {
    let toks = flat(&syntax::rhai::tokenize("let b = true;"));
    assert!(has(&toks, SyntaxToken::Boolean, "true"));
}

#[test]
fn rhai_tolerates_unterminated_string_and_keeps_colouring_later_lines() {
    // an unterminated `"` on line 1 must not swallow line 2's keyword
    let src = "let s = \"oops\nlet y = 1;";
    let lines = syntax::rhai::tokenize(src);
    assert_eq!(lines.len(), 2);
    assert!(has(&lines[1], SyntaxToken::Keyword, "let"));
    assert!(has(&lines[1], SyntaxToken::Number, "1"));
}

#[test]
fn rhai_block_comment_spans_lines() {
    let src = "/* a\n b */ let z = 1;";
    let lines = syntax::rhai::tokenize(src);
    assert!(lines[0].iter().any(|(k, _)| *k == SyntaxToken::Comment));
    assert!(lines[1].iter().any(|(k, _)| *k == SyntaxToken::Comment));
    // code after the close is coloured again
    assert!(has(&lines[1], SyntaxToken::Keyword, "let"));
}

#[test]
fn yaml_colours_key_value_bool_number_comment() {
    let src = "id: demo\ninfo:\n  severity: high # note\n  count: 3\n  flag: true";
    let lines = syntax::yaml::tokenize(src);
    let toks = flat(&lines);
    assert!(has(&toks, SyntaxToken::Key, "id"));
    assert!(has(&toks, SyntaxToken::Key, "severity"));
    assert!(has(&toks, SyntaxToken::Number, "3"));
    assert!(has(&toks, SyntaxToken::Boolean, "true"));
    assert!(toks
        .iter()
        .any(|(k, t)| *k == SyntaxToken::Comment && t.contains("# note")));
}

#[test]
fn yaml_tolerates_odd_lines() {
    // bare lines with no `key:` must still render, not panic
    let lines = syntax::yaml::tokenize(":::\n- \n   weird");
    assert_eq!(lines.len(), 3);
}

#[test]
fn highlight_reproduces_the_source_exactly() {
    let theme = Theme::new(true);
    let src = "fn f() { let x = 1; }";
    let rendered: String = syntax::highlight_rhai(&theme, src)
        .iter()
        .flat_map(|l| l.spans.iter().map(|s| s.content.to_string()))
        .collect();
    assert_eq!(rendered, src);

    let y = "id: demo\n  severity: high";
    let rendered_y: String = syntax::highlight_yaml(&theme, y)
        .iter()
        .map(|l| {
            l.spans
                .iter()
                .map(|s| s.content.as_ref())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(rendered_y, y);
}
