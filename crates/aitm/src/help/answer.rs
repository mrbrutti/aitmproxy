//! From a `HelpRequest` to a rendered page, a typed usage error, or "not help"
//! (plan Task 14; C31, C33): the mode topics render without a registry;
//! everything else reads the config (read-only; defaults plus one warning when
//! it cannot be read), builds `describe::registry` and locates the topic
//! through `aitm_cli::Cli::locate`. An implicit request that names nothing is
//! `NotHelp` and the invocation continues as `Mode::Cli`; an explicit one is
//! an error pre-boot.
//!
//! Nothing here creates a file or directory, opens a log, installs a tracing
//! subscriber, spawns a process or binds (plan rule 12): the config is read
//! through `config_file::load_settings`, the environment through the caller's
//! closure, and the registry is `describe::registry`'s inert one.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use aitm_cli::dispatch::Located;
use aitm_cli::Cli;
use aitm_core::Config;
use aitm_plugin_rhai::RhaiConfig;
use aitm_proto_l4::config::L4Config;
use aitm_sysproxy::SystemProxyConfig;
use aitm_term::caps::Caps;
use aitm_term::error::ErrorReport;
use aitm_term::help::HelpPage;
use aitm_term::reporter::Reporter;

use crate::config_file::{self, Settings};
use crate::describe::{self, DescribeInputs};
use crate::help::pages;
use crate::help::request::HelpRequest;
use crate::macos_capture::config::MacosCaptureConfig;

/// The three mode topics, answered from constants without a registry (plan
/// Task 14): `aitm web --help`, `aitm tui --help`, `aitm operator-token
/// --help`.
const WEB_TOPIC: &str = "web";
const TUI_TOPIC: &str = "tui";
const OPERATOR_TOKEN_TOPIC: &str = "operator-token";

/// What [`answer`] reads: the config file (`--config` or `AITM_CONFIG`; `None`
/// is the default path), the `--script` entries, an environment lookup
/// (injected, so tests never touch the process env), stdout's capabilities
/// (plan C49) and the version the top page prints.
pub struct HelpInputs<'a> {
    pub config_path: Option<&'a Path>,
    pub script_args: &'a [PathBuf],
    pub env: &'a dyn Fn(&str) -> Option<String>,
    pub caps: &'a Caps,
    pub version: &'a str,
}

/// What a help request comes to.
#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    /// The rendered page, for stdout; exit 0.
    Page(String),
    /// An explicit request that cannot be answered (`aitm help scpe`, `aitm
    /// scope ad --help`), as the dispatcher's typed usage error — did-you-mean
    /// and the help pointer included, no log footer (pre-boot, M-W2-4) — or a
    /// failure when the registry itself could not be built.
    Error(ErrorReport),
    /// An implicit single token that names no group (`aitm scpe`): the
    /// invocation continues as `Mode::Cli` and the dispatcher answers after
    /// boot (plan C33).
    NotHelp,
}

/// The settings help is built from (plan C31): the config file as
/// `config_file::load_settings` reads it, or `Settings` defaults after one
/// warning — `config not read · <path>: <first line of the error> · help
/// lists the default command set` — when it cannot be read or parsed. Help
/// never fails on the config; `strict` and a missing `--config` file are boot
/// concerns.
pub fn settings_for_help(config_path: Option<&Path>, reporter: &Reporter) -> Settings {
    match config_file::load_settings(config_path) {
        Ok(settings) => settings,
        Err(err) => {
            let path = config_path.map_or_else(config_file::default_config_path, Path::to_path_buf);
            reporter.warn(&format!(
                "config not read · {}: {} · help lists the default command set",
                path.display(),
                first_line(&err)
            ));
            default_settings()
        }
    }
}

/// Answer `req` (plan Task 14):
///
/// - topic `["web"]`, `["tui"]` or `["operator-token"]`: the mode page from
///   its constants — no config read, no registry built;
/// - otherwise the schema-only registry is built over
///   [`settings_for_help`]; a registry that cannot be built (the scripting
///   engine or its runtime, never a script) is `Answer::Error` as a failure;
/// - topic `[]`: the top page;
/// - else `Cli::locate(topic)`: a group is its group page, a command its verb
///   page (anything after the verb is ignored, so `aitm scope add --host
///   --help` is `scope add`'s page), and a usage error is `NotHelp` for an
///   implicit request and `Error` for an explicit one (plan C33).
pub fn answer(req: &HelpRequest, inputs: &HelpInputs, reporter: &Reporter) -> Answer {
    let topic: Vec<&str> = req.topic.iter().map(String::as_str).collect();
    match topic.as_slice() {
        [WEB_TOPIC] => return page(inputs.caps, &pages::web()),
        [TUI_TOPIC] => return page(inputs.caps, &pages::tui()),
        [OPERATOR_TOKEN_TOPIC] => return page(inputs.caps, &pages::operator_token()),
        _ => {}
    }

    let settings = settings_for_help(inputs.config_path, reporter);
    let described = match describe::registry(&DescribeInputs {
        settings: &settings,
        script_args: inputs.script_args,
        env: inputs.env,
    }) {
        Ok(described) => described,
        Err(err) => return Answer::Error(ErrorReport::failure(err.to_string())),
    };
    let registry = &described.registry;
    if req.topic.is_empty() {
        return page(inputs.caps, &pages::top_level(registry, inputs.version));
    }

    let cli = Cli::new(Arc::clone(registry));
    match cli.locate(&req.topic) {
        Ok(Located::Group { name, .. }) => match pages::group(registry, &name) {
            Some(group_page) => page(inputs.caps, &group_page),
            // `locate` found the group in this same registry, so its page
            // exists; a `None` here would be a registry that changed under us.
            None => Answer::Error(ErrorReport::failure(format!(
                "no help page for the group `{name}`"
            ))),
        },
        Ok(Located::Command { cmd, .. }) => page(inputs.caps, &pages::verb(cmd.as_ref())),
        Err(report) if req.explicit => Answer::Error(report),
        Err(_) => Answer::NotHelp,
    }
}

/// `page` rendered for `caps` (plan C49: stdout's).
fn page(caps: &Caps, page: &HelpPage) -> Answer {
    Answer::Page(pages::render(caps, page))
}

/// The first line of the error's root cause: `load_settings`'s context
/// layers (`in config file <path>`, `parsing config YAML`) only repeat the
/// path the warning already names; the cause is the line the operator needs.
fn first_line(err: &anyhow::Error) -> String {
    err.root_cause()
        .to_string()
        .lines()
        .next()
        .unwrap_or_default()
        .to_string()
}

/// `Settings` defaults, field by field (the type has no `Default`): what help
/// lists when the config cannot be read.
fn default_settings() -> Settings {
    Settings {
        core: Config::default(),
        rhai: RhaiConfig::default(),
        l4: L4Config::default(),
        macos_capture: MacosCaptureConfig::default(),
        system_proxy: SystemProxyConfig::default(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    use aitm_term::caps::{Caps, Verbosity};
    use aitm_term::error::{ErrorKind, FixCommand};
    use aitm_term::reporter::Reporter;
    use aitm_term::testing::SharedSink;

    use super::*;
    use crate::help::pages::{OPERATOR_TOKEN_USAGE_LINE, TUI_USAGE_LINE, WEB_USAGE_LINE};
    use crate::help::request::HelpRequest;

    /// The shipped catalogue, reached through the injected env (plan rule 13).
    const BUNDLED: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../scripts/bundled");

    /// The env of a page built with the catalogue (19 groups, M-W2-1).
    const CATALOGUE_ENV: &[(&str, &str)] = &[("AITM_BUNDLED_SCRIPTS", BUNDLED)];

    /// The env of a page built without it (17 groups, plan C30).
    const NO_CATALOGUE_ENV: &[(&str, &str)] = &[("AITM_NO_BUNDLED_SCRIPTS", "1")];

    /// The version the top page is built with: injected, so the literal is
    /// stable.
    const VERSION: &str = "0.5.11";

    /// A config file that parses and changes nothing (the default listen
    /// address), so a test reads a real file and never the operator's.
    const VALID_CONFIG: &str = "listen: 127.0.0.1:8080\n";

    /// What a UTF-8 pipe gets (plan rule 13): no colour, no animation, the
    /// `·` kept (`Caps::plain()` would print it as `-`).
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

    /// A reporter over an in-memory sink; read the sink after `finish()`.
    fn reporter() -> (Reporter, SharedSink) {
        let sink = SharedSink::new();
        let reporter = Reporter::new(piped_utf8(), Box::new(sink.clone()), Verbosity::Normal);
        (reporter, sink)
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// An explicit request (`aitm help <topic…>`).
    fn explicit(topic: &[&str]) -> HelpRequest {
        let mut argv = vec!["help".to_string()];
        argv.extend(args(topic));
        HelpRequest {
            topic: args(topic),
            explicit: true,
            argv,
        }
    }

    /// An implicit request (`aitm <token>`).
    fn implicit(token: &str) -> HelpRequest {
        HelpRequest {
            topic: args(&[token]),
            explicit: false,
            argv: args(&[token]),
        }
    }

    fn env_map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// A config file under a task-unique temp directory, removed on drop.
    struct TempConfig {
        dir: PathBuf,
        path: PathBuf,
    }

    impl TempConfig {
        fn new(tag: &str, text: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("aitm-help-answer-{tag}-{}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("temp config dir");
            let path = dir.join("config.yaml");
            std::fs::write(&path, text).expect("temp config file");
            Self { dir, path }
        }
    }

    impl Drop for TempConfig {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// `answer` over a valid temp config, `env`, the UTF-8 pipe caps and
    /// [`VERSION`]; the reporter's sink text is returned with the answer.
    fn ask(tag: &str, req: &HelpRequest, env: &[(&str, &str)]) -> (Answer, String) {
        let config = TempConfig::new(tag, VALID_CONFIG);
        ask_with(Some(&config.path), req, env)
    }

    fn ask_with(
        config_path: Option<&Path>,
        req: &HelpRequest,
        env: &[(&str, &str)],
    ) -> (Answer, String) {
        let env = env_map(env);
        let lookup = |key: &str| env.get(key).cloned();
        let caps = piped_utf8();
        let (reporter, sink) = reporter();
        let answer = answer(
            req,
            &HelpInputs {
                config_path,
                script_args: &[],
                env: &lookup,
                caps: &caps,
                version: VERSION,
            },
            &reporter,
        );
        reporter.finish();
        (answer, sink.text())
    }

    fn page(answer: &Answer) -> &str {
        match answer {
            Answer::Page(text) => text,
            other => panic!("expected a page, got {other:?}"),
        }
    }

    fn error(answer: &Answer) -> &ErrorReport {
        match answer {
            Answer::Error(report) => report,
            other => panic!("expected an error, got {other:?}"),
        }
    }

    #[test]
    fn top_level_is_a_page() {
        let (answer, warned) = ask("top", &explicit(&[]), CATALOGUE_ENV);
        let text = page(&answer);
        assert!(text.starts_with("aitm 0.5.11 — "), "{text}");
        assert!(text.contains("\nGroups:\n  agent "), "{text}");
        // The catalogue's groups are in: the registry, not a static list
        // (AC-W2-6).
        assert!(text.contains("\n  check "), "{text}");
        assert!(text.contains("\n  l4 "), "{text}");
        assert!(text.contains("\n  scope "), "{text}");
        assert!(text.ends_with("Trust the CA:  aitm ca install\n"), "{text}");
        assert!(!text.as_bytes().contains(&0x1b), "{text:?}");
        assert_eq!(warned, "", "a valid config warns about nothing");
    }

    #[test]
    fn group_topic_is_the_group_page() {
        let (answer, warned) = ask("group", &implicit("scope"), CATALOGUE_ENV);
        let text = page(&answer);
        assert!(
            text.starts_with("aitm scope — which hosts are decrypted\n"),
            "{text}"
        );
        assert!(
            text.contains("\nVerbs:\n  add --host <host>         Add a host, host:port, or *.wildcard to Scope.\n"),
            "{text}"
        );
        assert_eq!(warned, "");
    }

    #[test]
    fn verb_topic_is_the_verb_page() {
        let (answer, warned) = ask("verb", &explicit(&["scope", "add"]), CATALOGUE_ENV);
        let text = page(&answer);
        assert!(
            text.starts_with("Add a host, host:port, or *.wildcard to Scope."),
            "{text}"
        );
        assert!(
            text.contains("\nUsage:\n  aitm scope add --host <host>\n"),
            "{text}"
        );
        assert!(
            text.contains(
                "\nFlags:\n  --host <string>           The scope entry to add. [required]\n"
            ),
            "{text}"
        );
        assert_eq!(warned, "");
        // Tokens after the verb are ignored: the same page (plan Task 14,
        // "any `rest` ignored"), as for `aitm scope add --host --help`.
        let (again, _) = ask(
            "verb-rest",
            &explicit(&["scope", "add", "extra"]),
            CATALOGUE_ENV,
        );
        assert_eq!(page(&again), text);
    }

    #[test]
    fn help_and_group_forms_are_identical() {
        let (by_word, _) = ask("forms-help", &explicit(&["scope"]), CATALOGUE_ENV);
        let (bare, _) = ask("forms-bare", &implicit("scope"), CATALOGUE_ENV);
        let flagged = HelpRequest {
            topic: args(&["scope"]),
            explicit: true,
            argv: args(&["scope", "--help"]),
        };
        let (by_flag, _) = ask("forms-flag", &flagged, CATALOGUE_ENV);
        assert!(matches!(by_word, Answer::Page(_)), "{by_word:?}");
        assert_eq!(
            by_word, bare,
            "`aitm help scope` equals `aitm scope` (AC-W2-7)"
        );
        assert_eq!(by_word, by_flag, "`aitm scope --help` is the same page");
    }

    #[test]
    fn scan_is_a_group() {
        let (answer, warned) = ask("scan", &implicit("scan"), NO_CATALOGUE_ENV);
        let text = page(&answer);
        assert!(text.starts_with("aitm scan — "), "{text}");
        assert!(
            text.contains("\nUsage:\n  aitm scan <verb> [--flag <value>]...\n"),
            "{text}"
        );
        assert_eq!(warned, "");
    }

    #[test]
    fn implicit_unknown_token_is_not_help() {
        let (answer, warned) = ask("implicit-unknown", &implicit("scpe"), NO_CATALOGUE_ENV);
        assert_eq!(answer, Answer::NotHelp);
        assert_eq!(warned, "", "the fall-through prints nothing");
    }

    #[test]
    fn explicit_unknown_token_is_an_error_with_did_you_mean() {
        let (answer, warned) = ask("explicit-unknown", &explicit(&["scpe"]), NO_CATALOGUE_ENV);
        let report = error(&answer);
        assert_eq!(report.what, "unknown command `scpe`");
        assert_eq!(report.why, vec!["did you mean: scope".to_string()]);
        assert_eq!(report.command, Some(FixCommand("aitm --help".into())));
        assert_eq!(report.kind, ErrorKind::Usage);
        assert_eq!(report.exit_code(), 2);
        assert_eq!(report.fix, None);
        assert_eq!(report.log, None, "pre-boot: no log footer (M-W2-4)");
        assert_eq!(warned, "");
    }

    #[test]
    fn explicit_unknown_verb_points_at_the_group() {
        let (answer, _) = ask(
            "explicit-unknown-verb",
            &explicit(&["scope", "ad"]),
            NO_CATALOGUE_ENV,
        );
        let report = error(&answer);
        assert_eq!(report.what, "unknown command `scope ad`");
        assert_eq!(report.why, vec!["did you mean: scope add".to_string()]);
        assert_eq!(report.command, Some(FixCommand("aitm scope".into())));
        assert_eq!(report.exit_code(), 2);
        assert!(
            !report.what.contains("scope.ad"),
            "never a dotted name in prose (AC-W2-4): {}",
            report.what
        );
    }

    #[test]
    fn mode_topics_render_without_a_registry() {
        // No config file at this path and an env that must never be asked:
        // reading the config would warn, building the registry would read the
        // env. Neither happens for a mode topic.
        let missing = std::env::temp_dir().join(format!(
            "aitm-help-answer-mode-{}-never/config.yaml",
            std::process::id()
        ));
        let no_env = |key: &str| -> Option<String> {
            panic!("a mode page must not build the registry (asked for {key})")
        };
        let caps = piped_utf8();
        let mut pages = Vec::new();
        for topic in ["web", "tui", "operator-token"] {
            let (reporter, sink) = reporter();
            let answer = answer(
                &explicit(&[topic]),
                &HelpInputs {
                    config_path: Some(&missing),
                    script_args: &[],
                    env: &no_env,
                    caps: &caps,
                    version: VERSION,
                },
                &reporter,
            );
            reporter.finish();
            assert_eq!(sink.text(), "", "{topic}: the config is not read");
            pages.push(page(&answer).to_string());
        }
        let [web, tui, token] = pages.as_slice() else {
            unreachable!("three topics")
        };
        assert!(web.contains("web operator UI"), "{web}");
        assert!(
            web.starts_with("aitm web — the proxy and the web operator UI\n"),
            "{web}"
        );
        let usage_of = |line: &str| {
            let bare = line.strip_prefix("Usage: ").expect("a Usage: line");
            format!("\nUsage:\n  {bare}\n")
        };
        assert!(web.contains(&usage_of(WEB_USAGE_LINE)), "{web}");
        assert!(tui.contains(&usage_of(TUI_USAGE_LINE)), "{tui}");
        assert!(
            token.contains(&usage_of(OPERATOR_TOKEN_USAGE_LINE)),
            "{token}"
        );
        assert!(!token.contains("token:"), "never a token value: {token}");
    }

    #[test]
    fn bad_config_falls_back_to_defaults_and_warns_once() {
        let config = TempConfig::new("bad", "listen: [\n");
        let (answer, warned) = ask_with(Some(&config.path), &explicit(&[]), NO_CATALOGUE_ENV);
        let text = page(&answer);
        // The default command set: the 17 built-in groups, the top page as
        // usual.
        assert!(text.starts_with("aitm 0.5.11 — "), "{text}");
        assert!(text.contains("\n  scope "), "{text}");
        assert!(!text.contains("\n  check "), "{text}");
        // Exactly one warning line, plain (`warning:`), the path and the
        // error's first line between the two `·` (plan C31).
        assert_eq!(warned.lines().count(), 1, "{warned:?}");
        assert!(
            warned.starts_with("warning: config not read · "),
            "{warned:?}"
        );
        assert!(
            warned.ends_with(" · help lists the default command set\n"),
            "{warned:?}"
        );
        let path_and_error = warned
            .strip_prefix("warning: config not read · ")
            .and_then(|s| s.strip_suffix(" · help lists the default command set\n"))
            .expect("the two fixed parts");
        let path_prefix = format!("{}: ", config.path.display());
        let reason = path_and_error
            .strip_prefix(path_prefix.as_str())
            .unwrap_or_else(|| panic!("the path then `: ` in {path_and_error:?}"));
        assert!(!reason.is_empty(), "{warned:?}");
        assert!(!reason.contains('\n'), "{warned:?}");
        assert!(
            !reason.contains(&config.path.display().to_string()),
            "the path is named once: {warned:?}"
        );
        // `settings_for_help` alone: defaults, and the same one line.
        let (reporter, sink) = reporter();
        let settings = settings_for_help(Some(&config.path), &reporter);
        reporter.finish();
        assert_eq!(settings.core.listen, aitm_core::Config::default().listen);
        assert!(!settings.l4.enabled);
        assert_eq!(sink.text(), warned);
    }

    #[test]
    fn answer_creates_nothing() {
        let dir = std::env::temp_dir().join(format!(
            "aitm-help-answer-creates-nothing-{}-never",
            std::process::id()
        ));
        assert!(!dir.exists(), "{}", dir.display());
        let config_path = dir.join("config.yaml");
        let (answer, warned) = ask_with(Some(&config_path), &implicit("scope"), NO_CATALOGUE_ENV);
        let text = page(&answer);
        assert!(
            text.starts_with("aitm scope — which hosts are decrypted\n"),
            "{text}"
        );
        assert!(!dir.exists(), "help created {}", dir.display());
        assert!(
            !config_path.exists(),
            "help created {}",
            config_path.display()
        );
        // A missing file is "config not read" too: defaults plus the one line.
        assert_eq!(warned.lines().count(), 1, "{warned:?}");
        assert!(
            warned.starts_with("warning: config not read · "),
            "{warned:?}"
        );
        assert!(
            warned.contains(&format!("{}: ", config_path.display())),
            "{warned:?}"
        );
        assert!(
            warned.ends_with(" · help lists the default command set\n"),
            "{warned:?}"
        );
    }

    // ---- tester, wave-2 pass 1 (AC-W2-2/3/7; plan C29, C31, C33) ----

    use crate::help::request;

    /// A help flag in a value position (`aitm scope add --host --help`) is
    /// the verb's page: `request::parse` keeps the leading tokens and
    /// `answer` ignores the rest (plan Task 14); with an unknown verb before
    /// the flags it is the group's did-you-mean.
    #[test]
    fn help_flag_in_a_value_position_is_the_verb_page() {
        let req =
            request::parse(&args(&["scope", "add", "--host", "--help"])).expect("a help request");
        assert_eq!(req.topic, args(&["scope", "add"]));
        assert!(req.explicit);
        let (answer, warned) = ask("value-position", &req, NO_CATALOGUE_ENV);
        let (plain, _) = ask(
            "value-position-plain",
            &explicit(&["scope", "add"]),
            NO_CATALOGUE_ENV,
        );
        assert_eq!(answer, plain);
        assert!(
            page(&answer).starts_with("Add a host, host:port, or *.wildcard to Scope."),
            "{}",
            page(&answer)
        );
        assert_eq!(warned, "");
        let req = request::parse(&args(&["scope", "ad", "--host", "x", "--help"]))
            .expect("a help request");
        let (answer, _) = ask("value-position-unknown", &req, NO_CATALOGUE_ENV);
        let report = error(&answer);
        assert_eq!(report.what, "unknown command `scope ad`");
        assert_eq!(report.why, vec!["did you mean: scope add".to_string()]);
        assert_eq!(report.command, Some(FixCommand("aitm scope".into())));
        assert_eq!(report.log, None);
    }

    /// `aitm help help` asks about a topic named `help`, which is neither a
    /// group nor a command: explicit, so a usage error pointing at the top
    /// page (no group is within two edits of `help`), exit 2. `aitm help
    /// --help` is the top page.
    #[test]
    fn help_help_is_an_unknown_topic_and_help_dash_help_is_the_top_page() {
        let req = request::parse(&args(&["help", "help"])).expect("a help request");
        assert_eq!(req.topic, args(&["help"]));
        let (answer, warned) = ask("help-help", &req, NO_CATALOGUE_ENV);
        let report = error(&answer);
        assert_eq!(report.what, "unknown command `help`");
        assert_eq!(report.why, Vec::<String>::new());
        assert_eq!(report.command, Some(FixCommand("aitm --help".into())));
        assert_eq!(report.exit_code(), 2);
        assert_eq!(warned, "");
        let req = request::parse(&args(&["help", "--help"])).expect("a help request");
        assert_eq!(req.topic, Vec::<String>::new());
        let (answer, _) = ask("help-dash-help", &req, NO_CATALOGUE_ENV);
        assert!(page(&answer).starts_with("aitm 0.5.11 — "));
    }

    /// A `--config` path that is a directory cannot be read: defaults plus
    /// the one warning, the page still prints, and the directory is left as
    /// it was — nothing created inside it (plan C31, rule 12).
    #[test]
    fn config_path_that_is_a_directory_warns_once_and_creates_nothing() {
        let dir = std::env::temp_dir().join(format!("aitm-help-answer-dir-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let (answer, warned) = ask_with(Some(&dir), &explicit(&["scope"]), NO_CATALOGUE_ENV);
        let entries = std::fs::read_dir(&dir).expect("readable").count();
        let _ = std::fs::remove_dir_all(&dir);
        let text = page(&answer);
        assert!(
            text.starts_with("aitm scope — which hosts are decrypted\n"),
            "{text}"
        );
        assert_eq!(warned.lines().count(), 1, "{warned:?}");
        assert!(
            warned.starts_with(&format!("warning: config not read · {}: ", dir.display())),
            "{warned:?}"
        );
        assert!(
            warned.ends_with(" · help lists the default command set\n"),
            "{warned:?}"
        );
        assert_eq!(
            entries, 0,
            "help created something under the config directory"
        );
    }

    /// Plan C33: an implicit single token that names no group falls through
    /// to the CLI. A dotted verb name (`aitm flow.list`, the dispatcher's
    /// compatibility form) names no group, so it is `NotHelp` — the one-shot
    /// runs — not the verb's page; `aitm help flow.list` (explicit) is the
    /// page.
    #[test]
    #[ignore = "DEFECT (tester, wave-2 pass 1): `answer` renders the verb page for an implicit dotted token; plan C33 says an implicit request that names no group is NotHelp. Un-ignore with the fix."]
    fn implicit_dotted_verb_token_is_not_help() {
        let (answer, warned) = ask("implicit-dotted", &implicit("flow.list"), NO_CATALOGUE_ENV);
        assert_eq!(
            answer,
            Answer::NotHelp,
            "C33: only a group answers an implicit request"
        );
        assert_eq!(warned, "");
        let (answer, _) = ask(
            "explicit-dotted",
            &explicit(&["flow.list"]),
            NO_CATALOGUE_ENV,
        );
        assert!(
            page(&answer).contains("\nUsage:\n  aitm flow list\n"),
            "{}",
            page(&answer)
        );
    }

    /// Plan C29/C31 end to end: a config that enables `l4` is read (never
    /// written) and the `l4` group gains the module's verbs behind the three
    /// bundled scripts, in registration order; without it the group is the
    /// three scripts alone.
    #[test]
    fn config_with_l4_enabled_grows_the_l4_group() {
        fn verb_rows(text: &str) -> Vec<&str> {
            text.lines()
                .skip_while(|l| *l != "Verbs:")
                .skip(1)
                .take_while(|l| !l.is_empty())
                .filter(|l| !l.starts_with("    "))
                .collect()
        }
        let config = TempConfig::new("l4", "l4:\n  enabled: true\n");
        let (answer, warned) = ask_with(Some(&config.path), &implicit("l4"), CATALOGUE_ENV);
        let text = page(&answer);
        assert_eq!(warned, "");
        assert!(
            text.starts_with("aitm l4 — raw packet recon, probes and capture (opt-in)\n"),
            "{text}"
        );
        let verbs = verb_rows(text);
        assert_eq!(verbs.len(), 25, "3 scripts + 22 natives: {verbs:?}");
        assert!(verbs[0].starts_with("  recon "), "{}", verbs[0]);
        assert!(verbs[1].starts_with("  tcp_probe "), "{}", verbs[1]);
        assert!(verbs[2].starts_with("  udp_probe "), "{}", verbs[2]);
        assert!(
            verbs.iter().any(|l| l.starts_with("  scope add --")),
            "{verbs:?}"
        );
        // The 109-column footer wraps at 80 (plan C40: `Text` paragraphs wrap).
        assert!(
            text.ends_with("\n\nMost l4 verbs need l4.enabled in the config and capture privilege; recon and the\nprobes are bundled scripts.\n"),
            "{text}"
        );
        assert!(!text.as_bytes().contains(&0x1b));
        let (answer, _) = ask("l4-bare", &implicit("l4"), CATALOGUE_ENV);
        let bare = verb_rows(page(&answer));
        assert_eq!(bare.len(), 3, "{bare:?}");
        // The config is read, not written: the file is byte-identical after.
        assert_eq!(
            std::fs::read_to_string(&config.path).expect("still there"),
            "l4:\n  enabled: true\n"
        );
    }
}
