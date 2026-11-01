//! Capability detection (spec D2, T1, T2, T5; plan C8, C21, C22).
//!
//! [`Caps`] says what the stream we write to can show: whether it is a
//! terminal, whether colour, rich glyphs and in-place drawing are allowed, how
//! wide it is and whether we are under CI. [`Caps::from_parts`] is pure so
//! unit tests drive it with a fake environment; [`Caps::detect_stderr`] feeds
//! it the real one.

use std::io::IsTerminal;

/// The `--color` flag (spec T2: it beats every environment variable).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ColorChoice {
    #[default]
    Auto,
    Always,
    Never,
}

/// `AITM_TERM=rich|ascii|plain`, the operator's override hatch (spec D2 rule 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TermMode {
    Rich,
    Ascii,
    Plain,
}

impl TermMode {
    /// The mode named by an `AITM_TERM` value, matched case-insensitively;
    /// `None` for anything that is not one of the three words.
    pub fn from_env_value(value: &str) -> Option<TermMode> {
        if value.eq_ignore_ascii_case("rich") {
            Some(TermMode::Rich)
        } else if value.eq_ignore_ascii_case("ascii") {
            Some(TermMode::Ascii)
        } else if value.eq_ignore_ascii_case("plain") {
            Some(TermMode::Plain)
        } else {
            None
        }
    }
}

/// How much the reporter says (spec D4): `-q`, the default, `-v`, `-vv`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verbosity {
    Quiet,
    #[default]
    Normal,
    Verbose,
    Debug,
}

/// What the written stream can show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    /// The written stream is a terminal.
    pub tty: bool,
    /// SGR colour and attributes may be emitted.
    pub color: bool,
    /// Rich (UTF-8) glyphs instead of their ASCII twins.
    pub unicode: bool,
    /// In-place drawing and the spinner.
    pub animate: bool,
    /// Columns; 80 when unknown (spec T5).
    pub width: u16,
    /// `CI` is set (with any value, including empty; plan C22).
    pub ci: bool,
}

/// The width assumed when none can be measured (spec T5).
const DEFAULT_WIDTH: u16 = 80;

impl Caps {
    /// Detect stderr's capabilities from the process environment.
    ///
    /// The width is measured only after `stderr` is known to be a terminal
    /// (crossterm opens `/dev/tty` first and would return a width for a pipe;
    /// spec T5). A reported width of zero counts as unknown.
    pub fn detect_stderr(color: ColorChoice) -> Caps {
        let tty = std::io::stderr().is_terminal();
        let width = if tty {
            crossterm::terminal::size()
                .ok()
                .map(|(cols, _rows)| cols)
                .filter(|cols| *cols > 0)
        } else {
            None
        };
        Self::from_parts(tty, width, color, &|key| std::env::var(key).ok())
    }

    /// The pure half of detection, in spec D2's precedence order.
    ///
    /// 1. `--color=never|always` decides colour outright.
    /// 2. `AITM_TERM=plain` kills colour, glyphs and animation; `ascii` kills
    ///    glyphs; `rich` forces glyphs (animation still needs a TTY).
    /// 3. `NO_COLOR` non-empty disables colour, else `CLICOLOR_FORCE`
    ///    non-empty forces it.
    /// 4. Otherwise colour needs a TTY and a `TERM` that is set and not `dumb`.
    /// 5. Animation needs a TTY, that same `TERM`, no `CI` and a mode other
    ///    than plain; it does not depend on colour.
    /// 6. Glyphs are rich when any of `LC_ALL`, `LC_CTYPE`, `LANG` ends in
    ///    `UTF-8`/`UTF8` (case-insensitive) and `TERM` is not `linux`.
    pub fn from_parts(
        stream_is_tty: bool,
        measured_width: Option<u16>,
        color: ColorChoice,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Caps {
        let mode = env("AITM_TERM")
            .as_deref()
            .and_then(TermMode::from_env_value);
        let term = env("TERM");
        // An empty `TERM` names no terminal type: treat it as unset.
        let term_ok = term
            .as_deref()
            .is_some_and(|t| !t.is_empty() && t != "dumb");
        let ci = env("CI").is_some();
        let no_color = env("NO_COLOR").is_some_and(|v| !v.is_empty());
        let force_color = env("CLICOLOR_FORCE").is_some_and(|v| !v.is_empty());

        let color = match color {
            ColorChoice::Always => true,
            ColorChoice::Never => false,
            ColorChoice::Auto => {
                if mode == Some(TermMode::Plain) || no_color {
                    false
                } else if force_color {
                    true
                } else {
                    stream_is_tty && term_ok
                }
            }
        };

        let animate = stream_is_tty && term_ok && !ci && mode != Some(TermMode::Plain);

        let unicode = match mode {
            Some(TermMode::Rich) => true,
            Some(TermMode::Ascii) | Some(TermMode::Plain) => false,
            None => term.as_deref() != Some("linux") && locale_is_utf8(env),
        };

        Caps {
            tty: stream_is_tty,
            color,
            unicode,
            animate,
            width: measured_width.unwrap_or(DEFAULT_WIDTH),
            ci,
        }
    }

    /// No terminal, no colour, no glyphs, no animation, 80 columns: what a
    /// pipe, a file or a test sink gets.
    pub fn plain() -> Caps {
        Caps {
            tty: false,
            color: false,
            unicode: false,
            animate: false,
            width: DEFAULT_WIDTH,
            ci: false,
        }
    }

    /// The same capabilities with in-place drawing turned off (`-v`, `-vv`
    /// and `RUST_LOG` collapse the view to lines; spec D2 rule 5).
    pub fn without_animation(self) -> Caps {
        Caps {
            animate: false,
            ..self
        }
    }
}

/// Spec T1 / plan C21: any of `LC_ALL`, `LC_CTYPE`, `LANG` ends in
/// `utf-8` or `utf8`, case-insensitively.
fn locale_is_utf8(env: &dyn Fn(&str) -> Option<String>) -> bool {
    ["LC_ALL", "LC_CTYPE", "LANG"].iter().any(|key| {
        env(key).is_some_and(|value| {
            let lower = value.to_lowercase();
            lower.ends_with("utf-8") || lower.ends_with("utf8")
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// An environment made of the given pairs; every other name is unset.
    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k: &str| map.get(k).cloned()
    }

    /// A UTF-8 xterm login, the environment every TTY test starts from.
    const TTY_ENV: &[(&str, &str)] = &[("TERM", "xterm-256color"), ("LANG", "en_US.UTF-8")];

    /// `TTY_ENV` with the given pairs added or overridden.
    fn tty_env_with(extra: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let mut map: BTreeMap<String, String> = TTY_ENV
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        for (k, v) in extra {
            map.insert(k.to_string(), v.to_string());
        }
        move |k: &str| map.get(k).cloned()
    }

    /// A 120-column TTY with `--color=auto` in the given environment.
    fn on_tty(env: &dyn Fn(&str) -> Option<String>) -> Caps {
        Caps::from_parts(true, Some(120), ColorChoice::Auto, env)
    }

    fn rich() -> Caps {
        on_tty(&env_of(TTY_ENV))
    }

    #[test]
    fn caps_tty_utf8_xterm_is_rich() {
        assert_eq!(
            rich(),
            Caps {
                tty: true,
                color: true,
                unicode: true,
                animate: true,
                width: 120,
                ci: false,
            }
        );
    }

    #[test]
    fn caps_pipe_is_plain_but_keeps_locale_glyphs() {
        let caps = Caps::from_parts(false, None, ColorChoice::Auto, &env_of(TTY_ENV));
        assert_eq!(
            caps,
            Caps {
                tty: false,
                color: false,
                unicode: true,
                animate: false,
                width: 80,
                ci: false,
            }
        );
    }

    #[test]
    fn caps_term_dumb_or_unset_kills_color_and_animation() {
        let dumb = on_tty(&tty_env_with(&[("TERM", "dumb")]));
        assert!(!dumb.color, "TERM=dumb must disable colour");
        assert!(!dumb.animate, "TERM=dumb must disable animation");

        let unset = on_tty(&env_of(&[("LANG", "en_US.UTF-8")]));
        assert!(!unset.color, "an unset TERM must disable colour");
        assert!(!unset.animate, "an unset TERM must disable animation");
    }

    #[test]
    fn caps_no_color_non_empty_disables_color_but_not_animation() {
        let set = on_tty(&tty_env_with(&[("NO_COLOR", "1")]));
        assert!(!set.color);
        assert!(set.animate);

        let empty = on_tty(&tty_env_with(&[("NO_COLOR", "")]));
        assert!(empty.color, "an empty NO_COLOR is not set");
    }

    #[test]
    fn caps_clicolor_force_forces_color_on_a_pipe_but_no_color_wins() {
        let forced = Caps::from_parts(
            false,
            None,
            ColorChoice::Auto,
            &env_of(&[
                ("CLICOLOR_FORCE", "1"),
                ("TERM", "xterm"),
                ("LANG", "en_US.UTF-8"),
            ]),
        );
        assert!(forced.color);
        assert!(!forced.animate);

        let vetoed = Caps::from_parts(
            false,
            None,
            ColorChoice::Auto,
            &env_of(&[
                ("CLICOLOR_FORCE", "1"),
                ("NO_COLOR", "1"),
                ("TERM", "xterm"),
                ("LANG", "en_US.UTF-8"),
            ]),
        );
        assert!(!vetoed.color);
    }

    #[test]
    fn caps_color_flag_beats_every_variable() {
        let never = Caps::from_parts(
            true,
            Some(120),
            ColorChoice::Never,
            &tty_env_with(&[("CLICOLOR_FORCE", "1")]),
        );
        assert!(!never.color);

        let always = Caps::from_parts(
            true,
            Some(120),
            ColorChoice::Always,
            &tty_env_with(&[("NO_COLOR", "1")]),
        );
        assert!(always.color);
    }

    #[test]
    fn caps_aitm_term_modes() {
        let plain = on_tty(&tty_env_with(&[("AITM_TERM", "plain")]));
        assert!(!plain.color);
        assert!(!plain.unicode);
        assert!(!plain.animate);

        let ascii = on_tty(&tty_env_with(&[("AITM_TERM", "ascii")]));
        assert!(!ascii.unicode);
        assert!(ascii.color);
        assert!(ascii.animate);

        let rich = on_tty(&tty_env_with(&[("AITM_TERM", "rich"), ("LANG", "C")]));
        assert!(rich.unicode);
    }

    #[test]
    fn caps_unicode_follows_term_linux_and_the_locale() {
        let linux = on_tty(&env_of(&[("TERM", "linux"), ("LANG", "en_US.UTF-8")]));
        assert!(!linux.unicode);

        let c_locale = on_tty(&env_of(&[("TERM", "xterm-256color"), ("LANG", "C")]));
        assert!(!c_locale.unicode);

        let lc_all = on_tty(&env_of(&[
            ("TERM", "xterm-256color"),
            ("LC_ALL", "en_GB.utf8"),
        ]));
        assert!(lc_all.unicode);

        let lc_ctype = on_tty(&env_of(&[
            ("TERM", "xterm-256color"),
            ("LC_CTYPE", "UTF-8"),
        ]));
        assert!(lc_ctype.unicode);
    }

    #[test]
    fn caps_ci_means_plain_lines_on_a_tty() {
        let ci = on_tty(&tty_env_with(&[("CI", "true")]));
        assert!(!ci.animate);
        assert!(ci.ci);
        assert!(ci.color);

        let empty = on_tty(&tty_env_with(&[("CI", "")]));
        assert!(!empty.animate);
        assert!(empty.ci);
        assert!(empty.color);
    }

    #[test]
    fn caps_plain_constructor() {
        assert_eq!(
            Caps::plain(),
            Caps {
                tty: false,
                color: false,
                unicode: false,
                animate: false,
                width: 80,
                ci: false,
            }
        );

        let still = rich().without_animation();
        assert!(!still.animate);
        assert_eq!(
            still,
            Caps {
                animate: false,
                ..rich()
            }
        );
    }
}
