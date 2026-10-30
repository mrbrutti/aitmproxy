//! Key map: a crossterm key in a given [`Mode`] becomes an [`Action`]. The
//! verbs follow mitmproxy's console (foundation §2.1, §2.7 "Flow list →
//! Keyboard"): `i` intercept, `e` edit, `r` replay, `d` kill, `m` mark, `n`
//! compose, `a`/`A` resume (one / all), `p` pin, `P` build PoC; `:` opens the
//! palette and `/` the filter. Everything is reachable from the keyboard; the
//! mouse is optional (§2.9).

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::action::Action;
use crate::app::{Mode, PromptKind};
use crate::l4::L4Gate;
use crate::model::AgentPolicy;

/// Resolve a key for the current mode. `None` when the key means nothing here.
pub fn map(key: KeyEvent, mode: Mode) -> Option<Action> {
    if key.kind == KeyEventKind::Release {
        return None;
    }
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    // Global: Ctrl-C always leaves.
    if ctrl && key.code == KeyCode::Char('c') {
        return Some(Action::Quit);
    }
    match mode {
        Mode::Flows => flows(key, ctrl),
        Mode::Inspector | Mode::QuickLook => inspector(key),
        Mode::Edit => edit(key, ctrl),
        Mode::Prompt(kind) => prompt(key, kind, ctrl),
        Mode::Compose => compose(key, ctrl),
        Mode::Findings => findings(key),
        Mode::Scope => scope(key),
        Mode::Agent => agent(key),
        Mode::Ca => ca(key),
        Mode::Browser => browser(key),
        Mode::Scan => scan(key),
        // Read-only: back, palette, help.
        Mode::Config => panel(key),
        Mode::L4Confirm => l4_confirm(key),
        // Any key closes help (README); `:` goes straight to the palette.
        Mode::Help => Some(match key.code {
            KeyCode::Char(':') => Action::PaletteOpen,
            _ => Action::Back,
        }),
    }
}

/// A read-only panel: back, palette, help.
fn panel(key: KeyEvent) -> Option<Action> {
    Some(match key.code {
        KeyCode::Esc | KeyCode::Char('q') => Action::Back,
        KeyCode::Char(':') => Action::PaletteOpen,
        KeyCode::Char('?') => Action::Help,
        _ => return None,
    })
}

/// The CA panel: `e` export prompt; `i`/`u` run the confirmed tools by name
/// (the same path as typing `:ca.install`, so a bus without the CA plugin
/// answers with the missing tool's name).
fn ca(key: KeyEvent) -> Option<Action> {
    Some(match key.code {
        KeyCode::Char('e') => Action::CaExportPrompt,
        KeyCode::Char('i') => Action::Command("ca.install".into()),
        KeyCode::Char('u') => Action::Command("ca.uninstall".into()),
        _ => return panel(key),
    })
}

/// The browser view (§2.7, task 10): `g` URL prompt, `e` eval prompt, `d`
/// re-read the DOM, `s` screenshot, `o` open it, ↑↓ walk the outline. `g`
/// is the URL here, so Home is the key for "top of the outline".
fn browser(key: KeyEvent) -> Option<Action> {
    Some(match key.code {
        KeyCode::Char('g') => Action::BrowserNavigatePrompt,
        KeyCode::Char('e') => Action::BrowserEvalPrompt,
        KeyCode::Char('d') => Action::BrowserRefreshDom,
        KeyCode::Char('s') => Action::BrowserScreenshot,
        KeyCode::Char('o') => Action::OpenExternally,
        KeyCode::Up | KeyCode::Char('k') => Action::Up,
        KeyCode::Down | KeyCode::Char('j') => Action::Down,
        KeyCode::PageUp => Action::PageUp,
        KeyCode::PageDown => Action::PageDown,
        KeyCode::Home => Action::Home,
        KeyCode::End | KeyCode::Char('G') => Action::End,
        _ => return panel(key),
    })
}

/// The Scan view (scanner-integration Stage 1): ↑↓ walk the focused list, Tab
/// switches focus between the endpoints and the injection points, `r` launches
/// the scope-bound crawl (the only key that does), `F` jumps to the findings
/// pane, `:` palette, `?` help, Esc/`q` back.
fn scan(key: KeyEvent) -> Option<Action> {
    if let Some(a) = nav(key) {
        return Some(a);
    }
    Some(match key.code {
        KeyCode::Esc | KeyCode::Char('q') => Action::Back,
        KeyCode::Char('r') => Action::ScanLaunch,
        // Switch the cursor between the endpoints and injection-points lists.
        KeyCode::Tab | KeyCode::BackTab => Action::ScanFocusToggle,
        // Open the focused list's selected flow in the inspector.
        KeyCode::Enter | KeyCode::Right => Action::Enter,
        KeyCode::Char('F') => Action::OpenFindings,
        KeyCode::Char(':') => Action::PaletteOpen,
        KeyCode::Char('?') => Action::Help,
        _ => return None,
    })
}

/// The shared list-navigation keys. A key with Control held is not navigation
/// (`Ctrl-K` opens the palette, `j`/`k` only move when pressed bare).
fn nav(key: KeyEvent) -> Option<Action> {
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return None;
    }
    Some(match key.code {
        KeyCode::Up | KeyCode::Char('k') => Action::Up,
        KeyCode::Down | KeyCode::Char('j') => Action::Down,
        KeyCode::PageUp => Action::PageUp,
        KeyCode::PageDown => Action::PageDown,
        KeyCode::Home | KeyCode::Char('g') => Action::Home,
        KeyCode::End | KeyCode::Char('G') => Action::End,
        _ => return None,
    })
}

fn flows(key: KeyEvent, ctrl: bool) -> Option<Action> {
    if let Some(a) = nav(key) {
        return Some(a);
    }
    Some(match key.code {
        KeyCode::Char('q') => Action::Quit,
        KeyCode::Char('?') => Action::Help,
        KeyCode::Enter => Action::Enter,
        KeyCode::Esc => Action::Back,
        KeyCode::Char('b') => Action::ToggleSidebar,
        KeyCode::Char('[') => Action::SidebarPrev,
        KeyCode::Char(']') => Action::SidebarNext,
        KeyCode::Tab | KeyCode::Right => Action::ChipNext,
        KeyCode::BackTab | KeyCode::Left => Action::ChipPrev,
        KeyCode::Char(c @ '1'..='9') => Action::ChipIndex(c as usize - '1' as usize),
        KeyCode::Char('0') => Action::ChipIndex(9),
        KeyCode::Char('i') => Action::ToggleIntercept,
        KeyCode::Char('a') => Action::Resume,
        KeyCode::Char('A') => Action::ResumeAll,
        KeyCode::Char('d') | KeyCode::Char('x') => Action::Kill,
        KeyCode::Char('e') => Action::Edit,
        KeyCode::Char('r') => Action::Replay,
        KeyCode::Char('n') => Action::Compose,
        KeyCode::Char('p') => Action::Pin,
        KeyCode::Char('m') => Action::Mark,
        KeyCode::Char('c') => Action::Comment,
        KeyCode::Char('P') => Action::BuildPoc,
        KeyCode::Char('F') => Action::OpenFindings,
        KeyCode::Char('S') => Action::OpenScope,
        KeyCode::Char('@') => Action::OpenAgent,
        KeyCode::Char('l') => Action::ToggleLayout,
        KeyCode::Char('t') => Action::ToggleAutoSelect,
        KeyCode::Char('y') => Action::CopyUrl,
        KeyCode::Char('o') => Action::OpenExternally,
        KeyCode::Char(' ') => Action::QuickLook,
        KeyCode::Char('/') => Action::FilterOpen,
        KeyCode::Char(':') => Action::PaletteOpen,
        KeyCode::Char('f') if ctrl => Action::FilterOpen,
        KeyCode::Char('k') if ctrl => Action::PaletteOpen,
        _ => return None,
    })
}

fn inspector(key: KeyEvent) -> Option<Action> {
    Some(match key.code {
        KeyCode::Esc | KeyCode::Char('q') => Action::Back,
        KeyCode::Tab | KeyCode::BackTab => Action::InspectorPaneToggle,
        KeyCode::Left | KeyCode::Char('h') => Action::InspectorTabPrev,
        KeyCode::Right | KeyCode::Char('l') => Action::InspectorTabNext,
        KeyCode::Up | KeyCode::Char('k') => Action::Up,
        KeyCode::Down | KeyCode::Char('j') => Action::Down,
        KeyCode::PageUp => Action::PageUp,
        KeyCode::PageDown | KeyCode::Char(' ') => Action::PageDown,
        KeyCode::Home | KeyCode::Char('g') => Action::Home,
        KeyCode::End | KeyCode::Char('G') => Action::End,
        KeyCode::Char('z') => Action::ToggleFold,
        KeyCode::Char('e') => Action::Edit,
        KeyCode::Char('a') => Action::Resume,
        KeyCode::Char('d') | KeyCode::Char('x') => Action::Kill,
        KeyCode::Char('r') => Action::Replay,
        KeyCode::Char('n') => Action::Compose,
        KeyCode::Char('P') => Action::BuildPoc,
        KeyCode::Char('y') => Action::CopyUrl,
        KeyCode::Char('o') => Action::OpenExternally,
        KeyCode::Char('i') => Action::ToggleIntercept,
        // L4 inspector (a no-op on a non-L4 flow): b build craft, s inject.
        KeyCode::Char('b') => Action::L4Build,
        KeyCode::Char('s') => Action::L4Inject,
        KeyCode::Char(':') => Action::PaletteOpen,
        KeyCode::Char('/') => Action::FilterOpen,
        KeyCode::Char('?') => Action::Help,
        _ => return None,
    })
}

/// The L4 inject confirm overlay: `y` confirms (re-issues with `_confirm`),
/// `n` / Esc cancels.
fn l4_confirm(key: KeyEvent) -> Option<Action> {
    Some(match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') => Action::L4Confirm(true),
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => Action::L4Confirm(false),
        _ => return None,
    })
}

fn edit(key: KeyEvent, ctrl: bool) -> Option<Action> {
    Some(match key.code {
        KeyCode::Esc => Action::Back,
        KeyCode::Char('s') if ctrl => Action::ApplyAndResume,
        KeyCode::F(5) => Action::ApplyAndResume,
        KeyCode::Char('r') if ctrl => Action::RevertEdit,
        KeyCode::Enter => Action::Enter,
        KeyCode::Backspace => Action::Backspace,
        KeyCode::Up => Action::Up,
        KeyCode::Down => Action::Down,
        KeyCode::Left => Action::Left,
        KeyCode::Right => Action::Right,
        KeyCode::Home => Action::Home,
        KeyCode::End => Action::End,
        KeyCode::Tab => Action::Input('\t'),
        KeyCode::Char(c) if !ctrl => Action::Input(c),
        _ => return None,
    })
}

fn prompt(key: KeyEvent, kind: PromptKind, ctrl: bool) -> Option<Action> {
    Some(match key.code {
        KeyCode::Esc => Action::Back,
        KeyCode::Enter => Action::Submit,
        KeyCode::Backspace => Action::Backspace,
        KeyCode::Up => Action::Up,
        KeyCode::Down => Action::Down,
        KeyCode::Tab if kind == PromptKind::Palette => Action::Down,
        KeyCode::BackTab if kind == PromptKind::Palette => Action::Up,
        KeyCode::Char(c) if !ctrl => Action::Input(c),
        _ => return None,
    })
}

fn compose(key: KeyEvent, ctrl: bool) -> Option<Action> {
    Some(match key.code {
        KeyCode::Esc => Action::Back,
        KeyCode::Enter if ctrl => Action::ComposeSend,
        KeyCode::Char('s') if ctrl => Action::ComposeSend,
        KeyCode::Enter => Action::Submit,
        KeyCode::Tab | KeyCode::Down => Action::Down,
        KeyCode::BackTab | KeyCode::Up => Action::Up,
        KeyCode::Backspace => Action::Backspace,
        KeyCode::Char(c) if !ctrl => Action::Input(c),
        _ => return None,
    })
}

fn findings(key: KeyEvent) -> Option<Action> {
    if let Some(a) = nav(key) {
        return Some(a);
    }
    Some(match key.code {
        KeyCode::Esc | KeyCode::Char('q') => Action::Back,
        KeyCode::Enter => Action::Enter,
        KeyCode::Char('r') => Action::PocRerun,
        KeyCode::Char('o') => Action::OpenExternally,
        KeyCode::Char(':') => Action::PaletteOpen,
        KeyCode::Char('?') => Action::Help,
        _ => return None,
    })
}

fn scope(key: KeyEvent) -> Option<Action> {
    if let Some(a) = nav(key) {
        return Some(a);
    }
    Some(match key.code {
        KeyCode::Esc | KeyCode::Char('q') => Action::Back,
        KeyCode::Char('a') | KeyCode::Char('n') | KeyCode::Char('+') => Action::ScopeAddPrompt,
        KeyCode::Char('d') | KeyCode::Char('x') | KeyCode::Char('-') => Action::ScopeRemoveSelected,
        KeyCode::Char(':') => Action::PaletteOpen,
        KeyCode::Char('?') => Action::Help,
        _ => return None,
    })
}

fn agent(key: KeyEvent) -> Option<Action> {
    Some(match key.code {
        KeyCode::Esc | KeyCode::Char('q') => Action::Back,
        KeyCode::Char('1') | KeyCode::Char('a') => Action::AgentSet(AgentPolicy::All),
        KeyCode::Char('2') | KeyCode::Char('r') => Action::AgentSet(AgentPolicy::ReadOnly),
        KeyCode::Char('3') | KeyCode::Char('p') => Action::AgentSet(AgentPolicy::Paused),
        // The per-feature L4 agent gates (L4OPS-AC11).
        KeyCode::Char('c') => Action::L4ToggleGate(L4Gate::Capture),
        KeyCode::Char('i') => Action::L4ToggleGate(L4Gate::Inject),
        KeyCode::Char('n') => Action::L4ToggleGate(L4Gate::Intercept),
        KeyCode::Char('w') => Action::L4ToggleGate(L4Gate::Widen),
        KeyCode::Up | KeyCode::Char('k') => Action::Up,
        KeyCode::Down | KeyCode::Char('j') => Action::Down,
        KeyCode::Char(':') => Action::PaletteOpen,
        KeyCode::Char('?') => Action::Help,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn flow_verbs_follow_mitmproxy() {
        assert_eq!(
            map(press(KeyCode::Char('i')), Mode::Flows),
            Some(Action::ToggleIntercept)
        );
        assert_eq!(
            map(press(KeyCode::Char('e')), Mode::Flows),
            Some(Action::Edit)
        );
        assert_eq!(
            map(press(KeyCode::Char('r')), Mode::Flows),
            Some(Action::Replay)
        );
        assert_eq!(
            map(press(KeyCode::Char('d')), Mode::Flows),
            Some(Action::Kill)
        );
        assert_eq!(
            map(press(KeyCode::Char('n')), Mode::Flows),
            Some(Action::Compose)
        );
        assert_eq!(
            map(press(KeyCode::Char(':')), Mode::Flows),
            Some(Action::PaletteOpen)
        );
        assert_eq!(
            map(press(KeyCode::Char('3')), Mode::Flows),
            Some(Action::ChipIndex(2))
        );
    }

    #[test]
    fn prompts_take_text_and_releases_are_ignored() {
        assert_eq!(
            map(press(KeyCode::Char('i')), Mode::Prompt(PromptKind::Filter)),
            Some(Action::Input('i'))
        );
        assert_eq!(
            map(press(KeyCode::Enter), Mode::Prompt(PromptKind::Palette)),
            Some(Action::Submit)
        );
        let mut rel = press(KeyCode::Char('q'));
        rel.kind = KeyEventKind::Release;
        assert_eq!(map(rel, Mode::Flows), None);
        let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(map(ctrl_c, Mode::Edit), Some(Action::Quit));
    }

    /// Q11: the README says any key closes help; `q` is a key.
    #[test]
    fn q_closes_help_instead_of_quitting() {
        assert_eq!(
            map(press(KeyCode::Char('q')), Mode::Help),
            Some(Action::Back)
        );
        assert_eq!(
            map(press(KeyCode::Char('x')), Mode::Help),
            Some(Action::Back)
        );
        assert_eq!(
            map(press(KeyCode::Char(':')), Mode::Help),
            Some(Action::PaletteOpen)
        );
    }

    /// Q-1: a panel key is an `Action` variant, never a string pseudo-command
    /// that `run_command` has to recognise.
    #[test]
    fn panel_keys_are_action_variants_not_pseudo_commands() {
        for (key, mode, want) in [
            ('g', Mode::Browser, Action::BrowserNavigatePrompt),
            ('e', Mode::Browser, Action::BrowserEvalPrompt),
            ('d', Mode::Browser, Action::BrowserRefreshDom),
            ('s', Mode::Browser, Action::BrowserScreenshot),
            ('e', Mode::Ca, Action::CaExportPrompt),
            ('r', Mode::Findings, Action::PocRerun),
            ('a', Mode::Scope, Action::ScopeAddPrompt),
            ('n', Mode::Scope, Action::ScopeAddPrompt),
            ('+', Mode::Scope, Action::ScopeAddPrompt),
            ('d', Mode::Scope, Action::ScopeRemoveSelected),
            ('x', Mode::Scope, Action::ScopeRemoveSelected),
            ('-', Mode::Scope, Action::ScopeRemoveSelected),
        ] {
            assert_eq!(
                map(press(KeyCode::Char(key)), mode),
                Some(want),
                "{key} in {mode:?}"
            );
        }
        let ctrl_s = KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL);
        assert_eq!(map(ctrl_s, Mode::Compose), Some(Action::ComposeSend));
        let ctrl_enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL);
        assert_eq!(map(ctrl_enter, Mode::Compose), Some(Action::ComposeSend));
        // The CA panel's install/uninstall are the tool names, typed-command style.
        assert_eq!(
            map(press(KeyCode::Char('i')), Mode::Ca),
            Some(Action::Command("ca.install".into()))
        );
    }

    /// I2 / C2: the CA and Browser panels are keyboard-complete.
    #[test]
    fn ca_and_browser_panels_map_their_keys() {
        assert_eq!(
            map(press(KeyCode::Char('e')), Mode::Ca),
            Some(Action::CaExportPrompt)
        );
        assert_eq!(
            map(press(KeyCode::Char('i')), Mode::Ca),
            Some(Action::Command("ca.install".into()))
        );
        assert_eq!(
            map(press(KeyCode::Char('u')), Mode::Ca),
            Some(Action::Command("ca.uninstall".into()))
        );
        assert_eq!(map(press(KeyCode::Esc), Mode::Ca), Some(Action::Back));
        assert_eq!(
            map(press(KeyCode::Char('q')), Mode::Browser),
            Some(Action::Back)
        );
        assert_eq!(
            map(press(KeyCode::Char(':')), Mode::Browser),
            Some(Action::PaletteOpen)
        );
        assert_eq!(map(press(KeyCode::Char('z')), Mode::Browser), None);
        // Task 10: the browser view's verbs and outline navigation.
        for (key, want) in [
            ('g', Action::BrowserNavigatePrompt),
            ('e', Action::BrowserEvalPrompt),
            ('d', Action::BrowserRefreshDom),
            ('s', Action::BrowserScreenshot),
        ] {
            assert_eq!(
                map(press(KeyCode::Char(key)), Mode::Browser),
                Some(want),
                "{key}"
            );
        }
        assert_eq!(
            map(press(KeyCode::Char('o')), Mode::Browser),
            Some(Action::OpenExternally)
        );
        assert_eq!(map(press(KeyCode::Down), Mode::Browser), Some(Action::Down));
        assert_eq!(
            map(press(KeyCode::Char('j')), Mode::Browser),
            Some(Action::Down)
        );
        assert_eq!(map(press(KeyCode::Up), Mode::Browser), Some(Action::Up));
        assert_eq!(map(press(KeyCode::Home), Mode::Browser), Some(Action::Home));
        assert_eq!(map(press(KeyCode::End), Mode::Browser), Some(Action::End));
        assert_eq!(
            map(press(KeyCode::Char('?')), Mode::Browser),
            Some(Action::Help)
        );
        assert_eq!(map(press(KeyCode::Esc), Mode::Browser), Some(Action::Back));
        // The confirm prompt takes its answer as typed input.
        assert_eq!(
            map(press(KeyCode::Char('y')), Mode::Prompt(PromptKind::Confirm)),
            Some(Action::Input('y'))
        );
        assert_eq!(
            map(press(KeyCode::Esc), Mode::Prompt(PromptKind::Confirm)),
            Some(Action::Back)
        );
    }

    #[test]
    fn edit_mode_applies_with_ctrl_s() {
        let ctrl_s = KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL);
        assert_eq!(map(ctrl_s, Mode::Edit), Some(Action::ApplyAndResume));
        assert_eq!(
            map(press(KeyCode::Char('s')), Mode::Edit),
            Some(Action::Input('s'))
        );
        assert_eq!(
            map(press(KeyCode::Tab), Mode::Inspector),
            Some(Action::InspectorPaneToggle)
        );
    }
}
