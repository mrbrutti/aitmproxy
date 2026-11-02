//! Recognising a help request in argv (plan Task 11; C32, C33): `--help`,
//! `-h`, `help [topic…]` and `<group> [<verb>] --help` are explicit requests;
//! a single bare token that is not a mode word (`aitm scope`, `aitm scpe`) is
//! an implicit one; `sysproxy-watchdog` is never intercepted.
//!
//! [`parse`] is a pure function over the tokens `parse_invocation` has left
//! after the `--config`/`--script`/`--bus-endpoint-file` splits: no I/O, no
//! config, no registry. Whether a topic names a real group or verb is
//! `help::answer`'s question (plan Task 14); this module only decides *that*
//! the invocation asks for help and *what* it asks about.

/// The two help flags, recognised anywhere in argv (`aitm scope add --help`,
/// `aitm web --listen x -h`).
pub const HELP_FLAGS: &[&str] = &["--help", "-h"];

/// The help word: `aitm help [topic…]` is the same page as `aitm --help` and
/// `aitm <topic…> --help` (AC-W2-7).
pub const HELP_WORD: &str = "help";

/// The words that select a mode rather than a CLI group. Alone, none of them
/// is an implicit help request: `aitm tui` boots the TUI, `aitm version` is
/// `pre_boot`'s, `aitm help` is the top page by the explicit rule.
pub const MODE_WORDS: &[&str] = &[
    "tui",
    "web",
    "operator-token",
    "sysproxy-watchdog",
    "version",
    "help",
];

/// What a help invocation asks about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelpRequest {
    /// The leading non-flag tokens naming the page: `[]` for the top page,
    /// `["scope"]` for a group, `["scope", "add"]` for a verb, `["web"]` for
    /// a mode page.
    pub topic: Vec<String>,
    /// `true` when a help flag or the help word was given; `false` for a
    /// single bare token (`aitm scope`, `aitm scpe`), which falls through to
    /// the CLI when it names no group (C33).
    pub explicit: bool,
    /// The original argv, unchanged, so the implicit fall-through can continue
    /// as `Mode::Cli(argv)`.
    pub argv: Vec<String>,
}

/// Decide whether `argv` asks for help, and about what.
///
/// - `[]`, or `argv[0]` = `sysproxy-watchdog` (the hidden watchdog pins its
///   own usage line): `None`.
/// - `argv[0]` ∈ [`HELP_FLAGS`] ∪ {[`HELP_WORD`]}: explicit; the topic is
///   the leading non-flag tokens of `argv[1..]`.
/// - Otherwise any token ∈ [`HELP_FLAGS`]: explicit; the topic is the leading
///   non-flag tokens of `argv` (everything before the first `-`/`--` token).
/// - Otherwise a single token that is neither a flag nor in [`MODE_WORDS`]:
///   implicit, topic `[argv[0]]`.
/// - Otherwise `None`.
///
/// `argv` in the result is always the original slice.
pub fn parse(argv: &[String]) -> Option<HelpRequest> {
    let first = argv.first()?;
    if first == WATCHDOG {
        return None;
    }
    let request = |topic: Vec<String>, explicit: bool| {
        Some(HelpRequest {
            topic,
            explicit,
            argv: argv.to_vec(),
        })
    };
    if is_help_token(first) {
        return request(leading_topic(&argv[1..]), true);
    }
    if argv
        .iter()
        .any(|token| HELP_FLAGS.contains(&token.as_str()))
    {
        return request(leading_topic(argv), true);
    }
    if argv.len() == 1 && !is_flag(first) && !MODE_WORDS.contains(&first.as_str()) {
        return request(vec![first.clone()], false);
    }
    None
}

/// The hidden watchdog mode (`main.rs`'s `Mode::SysproxyWatchdog`); its own
/// parser answers every argument shape, `--help` included.
const WATCHDOG: &str = "sysproxy-watchdog";

/// A token that starts a flag: `--host`, `-h`, a bare `-` or `--`.
fn is_flag(token: &str) -> bool {
    token.starts_with('-')
}

/// `--help`, `-h` or `help`.
fn is_help_token(token: &str) -> bool {
    token == HELP_WORD || HELP_FLAGS.contains(&token)
}

/// The tokens before the first flag, cloned.
fn leading_topic(tokens: &[String]) -> Vec<String> {
    tokens
        .iter()
        .take_while(|token| !is_flag(token))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn request(topic: &[&str], explicit: bool, argv: &[&str]) -> Option<HelpRequest> {
        Some(HelpRequest {
            topic: args(topic),
            explicit,
            argv: args(argv),
        })
    }

    #[test]
    fn help_flags_and_the_help_word_alone_ask_for_the_top_page() {
        assert_eq!(parse(&args(&["--help"])), request(&[], true, &["--help"]));
        assert_eq!(parse(&args(&["-h"])), request(&[], true, &["-h"]));
        assert_eq!(parse(&args(&["help"])), request(&[], true, &["help"]));
    }

    #[test]
    fn help_word_topic_is_the_leading_non_flag_tokens() {
        assert_eq!(
            parse(&args(&["help", "scope"])),
            request(&["scope"], true, &["help", "scope"])
        );
        assert_eq!(
            parse(&args(&["help", "scope", "add"])),
            request(&["scope", "add"], true, &["help", "scope", "add"])
        );
    }

    #[test]
    fn a_help_flag_anywhere_makes_the_leading_tokens_the_topic() {
        assert_eq!(
            parse(&args(&["scope", "add", "--host", "x", "--help"])),
            request(
                &["scope", "add"],
                true,
                &["scope", "add", "--host", "x", "--help"]
            )
        );
        assert_eq!(
            parse(&args(&["scope", "--help"])),
            request(&["scope"], true, &["scope", "--help"])
        );
        assert_eq!(
            parse(&args(&["web", "--listen", "x", "-h"])),
            request(&["web"], true, &["web", "--listen", "x", "-h"])
        );
        assert_eq!(
            parse(&args(&["tui", "--help"])),
            request(&["tui"], true, &["tui", "--help"])
        );
    }

    #[test]
    fn a_single_bare_token_is_an_implicit_request() {
        assert_eq!(
            parse(&args(&["scope"])),
            request(&["scope"], false, &["scope"])
        );
        assert_eq!(
            parse(&args(&["scpe"])),
            request(&["scpe"], false, &["scpe"])
        );
    }

    #[test]
    fn mode_words_alone_are_not_help() {
        assert_eq!(parse(&args(&["tui"])), None);
        assert_eq!(parse(&args(&["web"])), None);
        assert_eq!(parse(&args(&["operator-token"])), None);
        assert_eq!(parse(&args(&["version"])), None);
        // Nothing in `MODE_WORDS` is ever an implicit request (`help` alone is
        // the explicit top page, checked above).
        for word in MODE_WORDS {
            let implicit = parse(&args(&[word])).is_some_and(|req| !req.explicit);
            assert!(
                !implicit,
                "`aitm {word}` must not be an implicit help request"
            );
        }
    }

    #[test]
    fn the_watchdog_is_never_intercepted() {
        assert_eq!(parse(&args(&["sysproxy-watchdog", "--help"])), None);
        assert_eq!(parse(&args(&["sysproxy-watchdog"])), None);
    }

    #[test]
    fn anything_else_is_not_help() {
        assert_eq!(parse(&args(&["--bad"])), None);
        assert_eq!(parse(&args(&["scope", "add", "--host", "x"])), None);
        assert_eq!(parse(&args(&[])), None);
    }
}
