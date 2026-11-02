//! The page builders (plan Task 13; C40–C43, C48): [`top_level`], [`group`]
//! and [`verb`] join the schema-only registry ([`crate::describe`]) with the
//! static catalogue ([`crate::help::catalog`]); [`web`], [`tui`] and
//! [`operator_token`] are the mode pages, built from constants; [`render`] is
//! `aitm_term::help::help_page` for the caller's [`Caps`] (stdout's, plan
//! C49), so a caller imports one module. The pages are plan mock-ups M-W2-1
//! (top), M-W2-2 (group), M-W2-3 (verb) and M-W2-7 (web).
//!
//! Shapes (plan C41–C43): the top page is titled `aitm <version> — <tagline>`
//! and its `Usage:` rows carry descriptions, so they are a section like every
//! other; a group page is titled `aitm <group> — <purpose>` and lists its
//! verbs with their required flags as `--name <name>` and the first sentence
//! of each description; a verb page has no title — it opens with the whole
//! description (cargo's shape) — then the usage form, the `Flags:` rows with
//! the type words and ` [required]`, the examples (the usage form when the
//! catalogue has none, which the catalogue pin forbids) and the group's
//! footer. Text the core composes is printed verbatim (plan rule 14).
//!
//! Nothing here reads the environment or touches a terminal: the caller
//! passes the registry it built and the `Caps` it measured (plan rule 12).

use std::fmt::Write as _;

use aitm_cli::dispatch::{group_of, group_usage_line, placeholder, spaced, type_hint, usage_form};
use aitm_core::{Command, Registry};
use aitm_term::caps::Caps;
use aitm_term::help::{help_page, Block, HelpPage, HelpRow, HelpSection};

use crate::describe;
use crate::help::catalog::{
    examples_for, group_info, GroupInfo, LEARN_MORE_ROWS, MODE_ROWS, NO_PURPOSE, OPTION_ROWS,
    TAGLINE, TOP_EXAMPLES, TOP_FOOTER,
};

/// The one `Usage:` line of `aitm web` (plan C48): the bare form on its page,
/// the cause line of its usage errors (M-W2-5).
pub const WEB_USAGE_LINE: &str =
    "Usage: aitm [--config <path>] web [--listen <addr>] [--token <token>] [--no-open]";

/// The one `Usage:` line of `aitm tui` (plan C48).
pub const TUI_USAGE_LINE: &str = "Usage: aitm [--config <path>] tui";

/// The one `Usage:` line of `aitm operator-token` (plan C48).
pub const OPERATOR_TOKEN_USAGE_LINE: &str =
    "Usage: aitm [--config <path>] operator-token generate [--force]";

/// What every `*_USAGE_LINE` starts with; a page's bare usage form is the rest
/// (the renderer writes the `Usage:` heading itself).
const USAGE_PREFIX: &str = "Usage: ";

/// The title's dash (plan C41; the renderer makes it ` - ` without Unicode).
const TITLE_DASH: &str = " — ";

/// The section headings, in the order the pages use them.
const USAGE_HEADING: &str = "Usage:";
const GROUPS_HEADING: &str = "Groups:";
const OPTIONS_HEADING: &str = "Options:";
const LEARN_MORE_HEADING: &str = "Learn more:";
const VERBS_HEADING: &str = "Verbs:";
const FLAGS_HEADING: &str = "Flags:";

/// Appended to a required flag's description on a verb page (plan C42).
const REQUIRED_MARK: &str = " [required]";

/// How many of its verbs' first examples a group page shows when the
/// catalogue has no entry for the group itself (plan C45).
const GROUP_EXAMPLES_MAX: usize = 4;

/// `aitm web --help` (M-W2-7): the option sentences are the former
/// `web::USAGE` text verbatim, hence capitalised; the Homebrew formula's
/// phrase `web operator UI` stays in the opening sentence (plan C48).
const WEB_TITLE: &str = "aitm web — the proxy and the web operator UI";
const WEB_ABOUT: &str = "Run the proxy (as `aitm` does) and also serve the web operator UI.";
const WEB_OPTION_ROWS: &[(&str, &str)] = &[
    (
        "--listen <addr>",
        "Bind address for the UI and its /bus bridge [default: 127.0.0.1:8082; env: AITM_WEB_LISTEN]",
    ),
    (
        "--token <token>",
        "Bridge token the UI must present as its first message [default: generated; env: AITM_WEB_TOKEN]",
    ),
    (
        "--no-open",
        "Do not open a browser (accepted; nothing is opened yet)",
    ),
    ("-h, --help", "Print this help"),
];
const WEB_FOOTER: &str = "Non-loopback addresses are refused until TLS for remote access lands (F15); use an SSH tunnel, or set AITM_WEB_INSECURE_BIND=1 to bind anyway.";

/// `aitm tui --help` (plan C48, the note under M-W2-7).
const TUI_TITLE: &str = "aitm tui — the proxy and the terminal operator UI";
const TUI_ABOUT: &str = "Run the proxy (as `aitm` does) and the terminal operator UI in this terminal; tracing goes to the log file, never to the screen.";

/// `aitm operator-token --help` (plan C48, the note under M-W2-7). The page
/// describes the token; it never carries one.
const OPERATOR_TOKEN_TITLE: &str = "aitm operator-token — the operator token";
const OPERATOR_TOKEN_ABOUT: &str = "Write a new random mcp.operator_token into the config file and print a confirmation (never the token); --force replaces an existing one. Restart aitm afterwards.";

/// The top page, `aitm --help` (M-W2-1; AC-W2-1): titled
/// `aitm <version> — <tagline>`; the `Usage:` rows of the modes, the `Groups:`
/// rows from the registry — alphabetical (plan C50), each with its catalogue
/// purpose or [`NO_PURPOSE`] — the `Options:` rows, the examples, the
/// `Learn more:` rows and the closing lines verbatim (`Block::Lines`: their
/// two-space gaps and adjacency are M-W2-1's). `usage` is empty: the mode
/// rows carry descriptions, so they are a section and align like every other.
pub fn top_level(registry: &Registry, version: &str) -> HelpPage {
    let groups = describe::groups(registry)
        .into_iter()
        .map(|(name, _)| {
            let purpose = group_info(&name).map_or(NO_PURPOSE, |info| info.purpose);
            row(&name, purpose)
        })
        .collect();
    HelpPage {
        title: format!("aitm {version}{TITLE_DASH}{TAGLINE}"),
        about: Vec::new(),
        usage: Vec::new(),
        blocks: vec![
            section(USAGE_HEADING, rows(MODE_ROWS)),
            section(GROUPS_HEADING, groups),
            section(OPTIONS_HEADING, rows(OPTION_ROWS)),
            Block::Examples(strings(TOP_EXAMPLES)),
            section(LEARN_MORE_HEADING, rows(LEARN_MORE_ROWS)),
            Block::Lines(strings(TOP_FOOTER)),
        ],
    }
}

/// A group page, `aitm <group>` (M-W2-2; AC-W2-2), or `None` when `name` is
/// not the group of any registered command (`scpe`, or a verb such as
/// `scope.add`). Titled `aitm <group> — <purpose>` ([`NO_PURPOSE`] without a
/// catalogue entry); the usage form `aitm <group> <verb> [--flag <value>]...`
/// (the same words as the dispatcher's bare-group error, plan C38); one
/// `Verbs:` row per command in registration order (plan C50) — [`verb_row`]
/// and [`first_sentence`] of its description; the catalogue's examples for the
/// group or, failing that, the first example of each verb, at most
/// [`GROUP_EXAMPLES_MAX`] (plan C45); the group's footer when it has one.
pub fn group(registry: &Registry, name: &str) -> Option<HelpPage> {
    let (_, commands) = describe::groups(registry)
        .into_iter()
        .find(|(group, _)| group == name)?;
    let info = group_info(name);
    let purpose = info.map_or(NO_PURPOSE, |info| info.purpose);
    let verbs = commands
        .iter()
        .map(|cmd| {
            let schema = cmd.schema();
            row(&verb_row(cmd.as_ref()), first_sentence(&schema.description))
        })
        .collect();
    let mut examples = strings(examples_for(name));
    if examples.is_empty() {
        examples = commands
            .iter()
            .filter_map(|cmd| examples_for(cmd.name()).first())
            .take(GROUP_EXAMPLES_MAX)
            .map(|example| (*example).to_string())
            .collect();
    }
    let mut blocks = vec![section(VERBS_HEADING, verbs)];
    if !examples.is_empty() {
        blocks.push(Block::Examples(examples));
    }
    blocks.extend(footer_block(info));
    Some(HelpPage {
        title: format!("aitm {name}{TITLE_DASH}{purpose}"),
        about: Vec::new(),
        usage: vec![bare(&group_usage_line(name))],
        blocks,
    })
}

/// A verb page, `aitm <group> <verb> --help` (M-W2-3; AC-W2-2): no title —
/// the whole description is the opening paragraph (cargo's shape, plan C43) —
/// the usage form (`aitm_cli::dispatch::usage_form`), a `Flags:` section when
/// the command has parameters with `--name <type>` on the left and the
/// parameter's description plus ` [required]` on the right (plan C42; the
/// core's words verbatim, so its `(default inline)` is the defaults
/// observable, C46), the catalogue's examples or the usage form when it has
/// none (plan C45), and the group's footer when it has one.
pub fn verb(cmd: &dyn Command) -> HelpPage {
    let schema = cmd.schema();
    let form = usage_form(cmd);
    let mut blocks = Vec::new();
    if !schema.params.is_empty() {
        let flags = schema
            .params
            .iter()
            .map(|def| {
                let mut description = def.description.clone();
                if def.required {
                    description.push_str(REQUIRED_MARK);
                }
                row(
                    &format!("--{} <{}>", def.name, type_hint(&def.ty)),
                    &description,
                )
            })
            .collect();
        blocks.push(section(FLAGS_HEADING, flags));
    }
    let examples = examples_for(cmd.name());
    blocks.push(Block::Examples(if examples.is_empty() {
        vec![form.clone()]
    } else {
        strings(examples)
    }));
    blocks.extend(footer_block(group_info(group_of(cmd.name()))));
    HelpPage {
        title: String::new(),
        about: vec![schema.description],
        usage: vec![form],
        blocks,
    }
}

/// `aitm web --help` (M-W2-7, plan C48).
pub fn web() -> HelpPage {
    HelpPage {
        title: WEB_TITLE.to_string(),
        about: vec![WEB_ABOUT.to_string()],
        usage: vec![bare(WEB_USAGE_LINE)],
        blocks: vec![
            section(OPTIONS_HEADING, rows(WEB_OPTION_ROWS)),
            Block::Text(vec![WEB_FOOTER.to_string()]),
        ],
    }
}

/// `aitm tui --help` (plan C48).
pub fn tui() -> HelpPage {
    HelpPage {
        title: TUI_TITLE.to_string(),
        about: vec![TUI_ABOUT.to_string()],
        usage: vec![bare(TUI_USAGE_LINE)],
        blocks: Vec::new(),
    }
}

/// `aitm operator-token --help` (plan C48).
pub fn operator_token() -> HelpPage {
    HelpPage {
        title: OPERATOR_TOKEN_TITLE.to_string(),
        about: vec![OPERATOR_TOKEN_ABOUT.to_string()],
        usage: vec![bare(OPERATOR_TOKEN_USAGE_LINE)],
        blocks: Vec::new(),
    }
}

/// The first sentence of a command description, verbatim (plan C43): the
/// text up to and including the first `.` that is followed by a space and an
/// uppercase letter, or the whole text when there is none — so `(e.g. colour
/// names)` and `{ url, param }` texts stay whole.
pub fn first_sentence(text: &str) -> &str {
    for (i, _) in text.match_indices('.') {
        let mut rest = text[i + 1..].chars();
        if rest.next() == Some(' ') && rest.next().is_some_and(char::is_uppercase) {
            return &text[..=i];
        }
    }
    text
}

/// A group page's left cell for `cmd` (plan C42): the words after the group
/// (`add`; `passthrough add` for `tls.passthrough.add`) followed by
/// ` --name <placeholder>` for each required flag in schema order; optional
/// flags are omitted (they are on the verb page's usage line).
pub fn verb_row(cmd: &dyn Command) -> String {
    let mut out = spaced(verb_of(cmd.name()));
    for def in cmd.schema().params.iter().filter(|def| def.required) {
        let _ = write!(out, " --{} {}", def.name, placeholder(def));
    }
    out
}

/// `page` rendered for `caps` — `aitm_term::help::help_page`, re-exported
/// here so a caller imports one module (plan Task 13). Plain text with no
/// escape byte unless `caps` both animates and allows colour (plan C6).
pub fn render(caps: &Caps, page: &HelpPage) -> String {
    help_page(caps, page)
}

/// The verb of a dotted command name: everything after its first segment
/// (`passthrough.add` for `tls.passthrough.add`); the whole name when it has
/// no dot.
fn verb_of(name: &str) -> &str {
    name.split_once('.').map_or(name, |(_, verb)| verb)
}

/// A `Usage: …` line without its prefix: the bare form a page's `usage`
/// field holds.
fn bare(usage_line: &str) -> String {
    usage_line
        .strip_prefix(USAGE_PREFIX)
        .unwrap_or(usage_line)
        .to_string()
}

/// The group's footer as a closing `Text` block, when it has one.
fn footer_block(info: Option<&GroupInfo>) -> Option<Block> {
    info.and_then(|info| info.footer)
        .map(|footer| Block::Text(vec![footer.to_string()]))
}

fn row(left: &str, right: &str) -> HelpRow {
    HelpRow {
        left: left.to_string(),
        right: right.to_string(),
    }
}

fn rows(pairs: &[(&str, &str)]) -> Vec<HelpRow> {
    pairs.iter().map(|(left, right)| row(left, right)).collect()
}

fn section(heading: &str, rows: Vec<HelpRow>) -> Block {
    Block::Section(HelpSection {
        heading: heading.to_string(),
        rows,
    })
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_string()).collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use aitm_core::{Command, CommandHost, Config, ParamSchema, Params, Registry, TypeDesc, Value};
    use aitm_plugin_rhai::RhaiConfig;
    use aitm_plugin_scanner::ScannerConfig;
    use aitm_proto_l4::config::L4Config;
    use aitm_sysproxy::SystemProxyConfig;
    use aitm_term::caps::Caps;
    use aitm_term::help::{Block, HelpRow, DESC_COL};
    use aitm_term::text;

    use super::*;
    use crate::config_file::Settings;
    use crate::describe::{self, DescribeInputs, Described};
    use crate::macos_capture::config::MacosCaptureConfig;

    /// The shipped catalogue, reached through the injected env (plan rule 13).
    const BUNDLED: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../scripts/bundled");

    /// The env of a page built with the catalogue (19 groups, M-W2-1).
    const CATALOGUE_ENV: &[(&str, &str)] = &[("AITM_BUNDLED_SCRIPTS", BUNDLED)];

    /// The env of a page built without it (18 groups, plan C30).
    const NO_CATALOGUE_ENV: &[(&str, &str)] = &[("AITM_NO_BUNDLED_SCRIPTS", "1")];

    /// The version the top page is built with: injected, so the literal is
    /// stable.
    const VERSION: &str = "0.5.11";

    /// The 18 built-in groups (catalogue off; `check` is native since the
    /// scanner v2 engine, main #232).
    const BUILT_IN_GROUPS: [&str; 18] = [
        "agent", "browser", "ca", "capture", "check", "config", "findings", "flow", "map", "poc",
        "proxy", "request", "scan", "scope", "script", "session", "tls", "ws",
    ];

    /// M-W2-1, byte for byte.
    const M_W2_1: &str = "\
aitm 0.5.11 — intercepting proxy for authorized security testing

Usage:
  aitm                      run the proxy with the MCP agent transport
  aitm web [options]        run the proxy and the web operator UI
  aitm tui                  run the proxy and the terminal operator UI
  aitm <group> <verb> [--flag <value>]...
                            run one command and exit
  aitm operator-token generate [--force]
                            write a new operator token into the config file

Groups:
  agent                     agent policy, approvals and the activity log
  browser                   drive the embedded browser
  ca                        the root CA: export, status, install, uninstall
  capture                   the macOS capture extension's status
  check                     active checks that confirm one finding at a URL
  config                    the running configuration, redacted
  findings                  the persistent findings store
  flow                      captured flows: list, inspect, intercept, replay
  l4                        raw packet recon, probes and capture (opt-in)
  map                       Map Local and Map Remote rules
  poc                       reproducible proofs of concept
  proxy                     proxy state, pause/resume and the system proxy
  request                   craft and send a request through the proxy
  scan                      discovery, passive checks and the findings report
  scope                     which hosts are decrypted
  script                    the Rhai detection scripts
  session                   save and load the flow store
  tls                       TLS passthrough: hosts tunnelled, not decrypted
  ws                        WebSocket frame interception and injection

Options:
  --config <path>           config file (env AITM_CONFIG)
  --script <path>           load an extra Rhai script (repeatable)
  --yes                     answer a verb's confirmation prompt without asking
  -v, -vv                   show INFO / DEBUG tracing on stderr
  -q                        errors only
  --color <auto|always|never>
                            force or disable colour (NO_COLOR, CLICOLOR_FORCE)
  --version, -V             print the version and exit
  --help, -h                print this help

Examples:
  $ aitm
  $ aitm web --no-open
  $ aitm scope add --host app.example.test
  $ aitm flow table

Learn more:
  aitm <group>              a group's verbs (aitm scope)
  aitm <group> <verb> --help
                            a verb's flags and examples (aitm scope add --help)
  aitm web --help           the web UI's options

Nothing is decrypted until a host is in Scope.  aitm scope add --host <host>
Trust the CA:  aitm ca install
";

    /// M-W2-2, byte for byte.
    const M_W2_2: &str = "\
aitm scope — which hosts are decrypted

Usage:
  aitm scope <verb> [--flag <value>]...

Verbs:
  add --host <host>         Add a host, host:port, or *.wildcard to Scope.
  remove --host <host>      Remove a scope entry (exact match).
  list                      List the current scope entries.

Examples:
  $ aitm scope add --host app.example.test
  $ aitm scope add --host '*.example.test'
  $ aitm scope list

Nothing is decrypted until a host is in Scope.
";

    /// M-W2-3, byte for byte.
    const M_W2_3: &str = "\
Add a host, host:port, or *.wildcard to Scope. New connections to it are
decrypted from now on; hosts outside Scope are tunnelled. Refused from an agent
frontend (MCP) unless scope.allow_agent_widen is set.

Usage:
  aitm scope add --host <host>

Flags:
  --host <string>           The scope entry to add. [required]

Examples:
  $ aitm scope add --host app.example.test
  $ aitm scope add --host '*.example.test'

Nothing is decrypted until a host is in Scope.
";

    /// M-W2-7, byte for byte.
    const M_W2_7: &str = "\
aitm web — the proxy and the web operator UI

Run the proxy (as `aitm` does) and also serve the web operator UI.

Usage:
  aitm [--config <path>] web [--listen <addr>] [--token <token>] [--no-open]

Options:
  --listen <addr>           Bind address for the UI and its /bus bridge
                            [default: 127.0.0.1:8082; env: AITM_WEB_LISTEN]
  --token <token>           Bridge token the UI must present as its first
                            message [default: generated; env: AITM_WEB_TOKEN]
  --no-open                 Do not open a browser (accepted; nothing is opened
                            yet)
  -h, --help                Print this help

Non-loopback addresses are refused until TLS for remote access lands (F15); use
an SSH tunnel, or set AITM_WEB_INSECURE_BIND=1 to bind anyway.
";

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

    /// `Settings` defaults with the CA pointed at a directory under the temp
    /// dir that must never come into existence (plan rule 12).
    fn settings(tag: &str) -> Settings {
        let mut core = Config::default();
        core.ca.dir = std::env::temp_dir().join(format!(
            "aitm-help-pages-{tag}-{}-never-created",
            std::process::id()
        ));
        Settings {
            core,
            rhai: RhaiConfig::default(),
            l4: L4Config::default(),
            macos_capture: MacosCaptureConfig::default(),
            system_proxy: SystemProxyConfig::default(),
            scanner: ScannerConfig::default(),
        }
    }

    /// The schema-only registry for `env`, built in-process (plan rule 13).
    fn registry_with(tag: &str, env: &[(&str, &str)]) -> Described {
        let settings = settings(tag);
        let env: BTreeMap<String, String> = env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let lookup = |key: &str| env.get(key).cloned();
        let described = describe::registry(&DescribeInputs {
            settings: &settings,
            script_args: &[],
            env: &lookup,
        })
        .expect("the schema-only registry builds");
        assert!(
            described.script_errors.is_empty(),
            "the catalogue compiles for help: {:?}",
            described.script_errors
        );
        assert!(
            !settings.core.ca.dir.exists(),
            "help must never create the CA directory (plan rule 12)"
        );
        described
    }

    /// The lines of the block headed `heading` in a rendered page: after the
    /// heading, up to the next blank line.
    fn block_lines<'a>(rendered: &'a str, heading: &str) -> Vec<&'a str> {
        rendered
            .lines()
            .skip_while(|line| *line != heading)
            .skip(1)
            .take_while(|line| !line.is_empty())
            .collect()
    }

    /// The `Groups:` section of a top page, from the model.
    fn groups_section(page: &HelpPage) -> &HelpSection {
        page.blocks
            .iter()
            .find_map(|block| match block {
                Block::Section(section) if section.heading == "Groups:" => Some(section),
                _ => None,
            })
            .expect("the top page has a Groups: section")
    }

    /// A schema-only command in a group the catalogue does not know.
    struct Zzz;

    impl Command for Zzz {
        fn name(&self) -> &str {
            "zzz.one"
        }
        fn schema(&self) -> ParamSchema {
            ParamSchema {
                description: "Do the one thing.".into(),
                params: Vec::new(),
                result: TypeDesc::Bool,
            }
        }
        fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
            anyhow::bail!("zzz.one is schema-only")
        }
    }

    #[test]
    fn top_level_matches_the_mockup_with_the_catalogue() {
        let described = registry_with("top", CATALOGUE_ENV);
        let out = render(&piped_utf8(), &top_level(&described.registry, VERSION));
        assert_eq!(out, M_W2_1);
        assert!(!out.as_bytes().contains(&0x1b), "{out:?}");
    }

    #[test]
    fn top_level_without_the_catalogue_has_eighteen_groups() {
        let described = registry_with("top-bare", NO_CATALOGUE_ENV);
        let page = top_level(&described.registry, VERSION);
        let out = render(&piped_utf8(), &page);

        let names: Vec<&str> = groups_section(&page)
            .rows
            .iter()
            .map(|row| row.left.as_str())
            .collect();
        assert_eq!(names, BUILT_IN_GROUPS);
        let rendered = block_lines(&out, "Groups:");
        assert_eq!(rendered.len(), 18, "{out}");
        assert!(
            !rendered.iter().any(|line| line.starts_with("  check ")),
            "{out}"
        );
        assert!(
            !rendered.iter().any(|line| line.starts_with("  l4 ")),
            "{out}"
        );
        assert_eq!(
            out.lines().next(),
            Some("aitm 0.5.11 — intercepting proxy for authorized security testing")
        );
        // The footer does not depend on the catalogue: the same two lines as
        // the catalogue page, and the W1 `term-reporting.sh` §1 literal.
        let with_catalogue = render(
            &piped_utf8(),
            &top_level(&registry_with("top-both", CATALOGUE_ENV).registry, VERSION),
        );
        let last_two = |s: &str| {
            s.lines()
                .rev()
                .take(2)
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        assert_eq!(last_two(&out), last_two(&with_catalogue));
        assert!(out.contains("aitm scope add --host <host>"), "{out}");
        assert!(out.contains("Trust the CA:"), "{out}");
    }

    #[test]
    fn scope_group_page_matches_the_mockup() {
        let described = registry_with("scope", CATALOGUE_ENV);
        let page = group(&described.registry, "scope").expect("scope is a group");
        let out = render(&piped_utf8(), &page);
        assert_eq!(out, M_W2_2);
        // The rich form is the same text with bold headings and dim
        // descriptions only (AC-W2-1).
        let rich = render(&tty80(), &page);
        assert!(rich.contains("\x1b[1mVerbs:\x1b[0m\n"), "{rich:?}");
        assert_eq!(text::strip_sgr(&rich), out);
    }

    #[test]
    fn scope_add_verb_page_matches_the_mockup() {
        let described = registry_with("scope-add", CATALOGUE_ENV);
        let cmd = described
            .registry
            .command("scope.add")
            .expect("scope.add is registered");
        let out = render(&piped_utf8(), &verb(cmd.as_ref()));
        assert_eq!(out, M_W2_3);
    }

    #[test]
    fn flow_detail_page_keeps_the_core_default_words() {
        let described = registry_with("flow-detail", NO_CATALOGUE_ENV);
        let cmd = described
            .registry
            .command("flow.detail")
            .expect("flow.detail is registered");
        let out = render(&piped_utf8(), &verb(cmd.as_ref()));
        assert!(out.contains("(default inline)"), "{out}");
        assert!(out.contains("(default 0)"), "{out}");
        assert!(
            out.contains(
                "Usage:\n  aitm flow detail --id <id> [--body <body>] [--offset <offset>]\n    [--length <length>]\n"
            ),
            "{out}"
        );
        // The flags carry the type words and the required mark (plan C42) and
        // the core's sentences verbatim (C46).
        assert!(
            out.contains("\nFlags:\n  --id <flow-id>            The flow to inspect. [required]\n"),
            "{out}"
        );
        assert!(
            out.contains(
                "  --body <string>           Body mode: `none`, `inline` (default), or `range`.\n"
            ),
            "{out}"
        );
        assert!(
            out.contains(
                "  --offset <int>            Byte offset for `body: range` (default 0).\n"
            ),
            "{out}"
        );
        assert!(out.starts_with("Full detail for one flow: "), "{out}");
        assert!(
            out.contains(
                "\nExamples:\n  $ aitm flow detail --id 3f2a9c1e-7b10-4c4d-9e21-04ad5b6c7d8e\n"
            ),
            "{out}"
        );
    }

    #[test]
    fn first_sentence_stops_at_a_sentence_end_not_inside_eg() {
        assert_eq!(
            first_sentence(
                "Add a host, host:port, or *.wildcard to Scope. New connections to it are decrypted."
            ),
            "Add a host, host:port, or *.wildcard to Scope."
        );
        let eg =
            "Replace a flow's highlight mark set (e.g. colour names); an empty array clears it.";
        assert_eq!(first_sentence(eg), eg);
        let braces = "Confirm SQL injection in { url, param, value? } (error + boolean)";
        assert_eq!(first_sentence(braces), braces);
        assert_eq!(first_sentence(""), "");
    }

    #[test]
    fn verb_row_uses_name_placeholders_and_omits_optional_flags() {
        let described = registry_with("verb-row", NO_CATALOGUE_ENV);
        let registry = &described.registry;
        let cmd = |name: &str| {
            Arc::clone(
                registry
                    .command(name)
                    .unwrap_or_else(|| panic!("{name} is registered")),
            )
        };
        assert_eq!(verb_row(cmd("flow.detail").as_ref()), "detail --id <id>");
        assert_eq!(
            verb_row(cmd("browser.confine").as_ref()),
            "confine --on <true|false>"
        );
        assert_eq!(verb_row(cmd("scope.list").as_ref()), "list");
        // A three-segment name shows the words the operator types after the
        // group.
        assert_eq!(
            verb_row(cmd("tls.passthrough.add").as_ref()),
            "passthrough add --host <host>"
        );
    }

    #[test]
    fn web_page_keeps_the_formula_phrase() {
        let out = render(&piped_utf8(), &web());
        assert_eq!(out, M_W2_7);
        assert!(out.contains("web operator UI"), "{out}");
        assert_eq!(
            WEB_USAGE_LINE,
            "Usage: aitm [--config <path>] web [--listen <addr>] [--token <token>] [--no-open]"
        );
        // The two other mode pages open with their title and carry their one
        // `Usage:` line (plan C48).
        let tui = render(&piped_utf8(), &tui());
        assert!(
            tui.starts_with("aitm tui — the proxy and the terminal operator UI\n\n"),
            "{tui}"
        );
        assert!(
            tui.contains("\nUsage:\n  aitm [--config <path>] tui\n"),
            "{tui}"
        );
        assert_eq!(TUI_USAGE_LINE, "Usage: aitm [--config <path>] tui");
        let token = render(&piped_utf8(), &operator_token());
        assert!(
            token.starts_with("aitm operator-token — the operator token\n\n"),
            "{token}"
        );
        assert!(
            token
                .contains("\nUsage:\n  aitm [--config <path>] operator-token generate [--force]\n"),
            "{token}"
        );
        assert_eq!(
            OPERATOR_TOKEN_USAGE_LINE,
            "Usage: aitm [--config <path>] operator-token generate [--force]"
        );
        assert!(!token.contains("token:"), "never a token value: {token}");
    }

    #[test]
    fn a_group_without_a_catalogue_entry_renders_the_placeholder() {
        let mut registry = Registry::new();
        registry.add_command(Arc::new(Zzz));
        let page = top_level(&registry, "0.0.0");
        assert_eq!(
            groups_section(&page).rows,
            vec![HelpRow {
                left: "zzz".to_string(),
                right: "(no description)".to_string(),
            }]
        );
        let out = render(&piped_utf8(), &page);
        assert!(
            out.contains("\nGroups:\n  zzz                       (no description)\n"),
            "{out}"
        );
        let group_page = group(&registry, "zzz").expect("zzz is a group");
        assert_eq!(group_page.title, "aitm zzz — (no description)");
        let out = render(&piped_utf8(), &group_page);
        assert!(out.starts_with("aitm zzz — (no description)\n\n"), "{out}");
        assert!(
            out.contains("\nVerbs:\n  one                       Do the one thing.\n"),
            "{out}"
        );
        // No catalogue entry for the group or its verb: nothing stands in
        // (the usage-form fallback is the verb page's, plan C45) and there is
        // no footer, so the page ends with its one verb.
        assert!(
            out.ends_with("\nVerbs:\n  one                       Do the one thing.\n"),
            "{out}"
        );
        assert!(!out.contains("Examples:"), "{out}");
    }

    #[test]
    fn unknown_group_is_none() {
        let described = registry_with("unknown", NO_CATALOGUE_ENV);
        assert!(group(&described.registry, "scpe").is_none());
        assert!(
            group(&described.registry, "scope.add").is_none(),
            "a verb is not a group"
        );
        assert!(group(&described.registry, "").is_none());
        assert!(group(&described.registry, "scope").is_some());
    }

    // ---- tester, wave-2 pass 1 (AC-W2-1/2; plan C40–C45, C50) ----

    /// The schema-only registry with `l4.enabled` for `env` (the widest set
    /// help can show), built in-process (plan rule 13).
    fn registry_with_l4(tag: &str, env: &[(&str, &str)]) -> Described {
        let mut settings = settings(tag);
        settings.l4.enabled = true;
        let env: BTreeMap<String, String> = env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let lookup = |key: &str| env.get(key).cloned();
        let described = describe::registry(&DescribeInputs {
            settings: &settings,
            script_args: &[],
            env: &lookup,
        })
        .expect("the schema-only registry builds");
        assert!(
            !settings.core.ca.dir.exists(),
            "help must never create the CA directory (plan rule 12)"
        );
        described
    }

    /// The rows of a rendered section as `(left, description words)`: a line
    /// that does not start at the description column opens a row, every
    /// following line at that column continues its description.
    fn rendered_rows(lines: &[&str]) -> Vec<(String, String)> {
        let mut rows: Vec<(String, String)> = Vec::new();
        for line in lines {
            if line.starts_with("    ") {
                let (_, desc) = rows.last_mut().expect("a continuation follows a row");
                desc.push(' ');
                desc.push_str(line.trim());
            } else {
                let body = &line[2..];
                let (left, desc) = match body.find("  ") {
                    Some(at) => (&body[..at], body[at..].trim()),
                    None => (body, ""),
                };
                rows.push((left.to_string(), desc.to_string()));
            }
        }
        rows
    }

    /// The top page at 40 and 200 columns: at 200 nothing wraps, so it is
    /// the 80-column mock-up; at 40 the 19 group rows keep the fixed column
    /// with at most twenty columns of description per line, the examples and
    /// the footer are printed whole, and every row's words are the same.
    #[test]
    fn top_level_renders_at_width_forty_and_two_hundred() {
        let described = registry_with("widths", CATALOGUE_ENV);
        let page = top_level(&described.registry, VERSION);
        let at = |width: u16| {
            render(
                &Caps {
                    width,
                    ..piped_utf8()
                },
                &page,
            )
        };
        let (narrow, wide, normal) = (at(40), at(200), at(80));
        assert_eq!(wide, M_W2_1);
        assert_eq!(normal, M_W2_1);
        assert_ne!(narrow, M_W2_1);
        let narrow_groups = block_lines(&narrow, "Groups:");
        assert!(narrow_groups.len() > 19, "{narrow}");
        for line in &narrow_groups {
            let desc = line.get(DESC_COL..).unwrap_or_default();
            assert!(text::width(desc) <= 20, "{line:?}");
            if !line.starts_with("    ") {
                assert_eq!(line.chars().nth(DESC_COL - 1), Some(' '), "{line:?}");
                assert_ne!(line.chars().nth(DESC_COL), Some(' '), "{line:?}");
            }
        }
        for heading in ["Usage:", "Groups:", "Options:", "Learn more:"] {
            let rows_narrow = rendered_rows(&block_lines(&narrow, heading));
            let rows_wide = rendered_rows(&block_lines(&wide, heading));
            assert_eq!(rows_narrow, rows_wide, "{heading} at 40 vs 200");
        }
        assert_eq!(rendered_rows(&block_lines(&narrow, "Groups:")).len(), 19);
        assert_eq!(
            block_lines(&narrow, "Examples:"),
            block_lines(&wide, "Examples:")
        );
        fn last_two(s: &str) -> Vec<&str> {
            s.lines().rev().take(2).collect()
        }
        assert_eq!(last_two(&narrow), last_two(&wide));
        assert_eq!(
            last_two(&narrow),
            vec![
                "Trust the CA:  aitm ca install",
                "Nothing is decrypted until a host is in Scope.  aitm scope add --host <host>",
            ]
        );
    }

    /// AC-W2-1's rich half, in-process (the `help.sh` §8 analogue): on a
    /// colour TTY the top page paints its five headings bold and its 35
    /// physical description lines dim — nothing else — and stripping the SGR
    /// gives the piped page back.
    #[test]
    fn top_level_rich_paints_five_headings_and_every_description_line() {
        let described = registry_with("rich", CATALOGUE_ENV);
        let rich = render(&tty80(), &top_level(&described.registry, VERSION));
        assert_eq!(rich.matches("\x1b[1m").count(), 5, "{rich:?}");
        assert_eq!(rich.matches("\x1b[2m").count(), 5 + 19 + 8 + 3, "{rich:?}");
        assert_eq!(rich.matches("\x1b[").count(), 2 * (5 + 35), "{rich:?}");
        // The title, the example lines and the two footer lines are never
        // painted; the headings are the only unindented lines that are.
        for line in rich.lines() {
            let plain = text::strip_sgr(line);
            let heading = !plain.starts_with(' ') && plain.ends_with(':');
            if plain.starts_with("  $ ") || (!plain.starts_with(' ') && !heading) {
                assert!(!line.as_bytes().contains(&0x1b), "{line:?}");
            }
        }
        assert_eq!(text::strip_sgr(&rich), M_W2_1);
    }

    /// An example wider than the terminal is printed whole (plan C40/C45):
    /// `map.add`'s catalogue line is wider than an 80-column page (its two
    /// JSON values cannot fit 76) and renders as one `  $ ` line at 80, at 40
    /// and at 200, at its own width plus the prompt.
    #[test]
    fn verb_page_prints_an_over_wide_example_whole_at_every_width() {
        let described = registry_with("map-add", NO_CATALOGUE_ENV);
        let cmd = described
            .registry
            .command("map.add")
            .expect("map.add is registered");
        let page = verb(cmd.as_ref());
        let example = examples_for("map.add")[0];
        let example_width = text::width(example);
        assert!(example_width > 80, "{example_width}: {example}");
        for width in [40u16, 80, 200] {
            let out = render(
                &Caps {
                    width,
                    ..piped_utf8()
                },
                &page,
            );
            assert!(
                out.contains(&format!("\nExamples:\n  $ {example}\n")),
                "{width}: {out}"
            );
            let line = out
                .lines()
                .find(|line| line.starts_with("  $ aitm map add "))
                .unwrap_or_else(|| panic!("{width}: {out}"));
            assert_eq!(text::width(line), 4 + example_width, "{width}: {line}");
        }
    }

    /// A three-segment group (`tls`) and the one-verb groups (`capture`,
    /// `config`, `request`): the verb rows show the words after the group
    /// with the required flags (plan C42/C50), the examples fall back to each
    /// verb's first (plan C45), there is no footer.
    #[test]
    fn group_pages_for_three_segment_and_one_verb_groups() {
        let described = registry_with("tls", NO_CATALOGUE_ENV);
        let reg = &described.registry;
        let tls = render(&piped_utf8(), &group(reg, "tls").expect("tls is a group"));
        assert!(
            tls.starts_with(
                "aitm tls — TLS passthrough: hosts tunnelled, not decrypted\n\nUsage:\n  aitm tls <verb> [--flag <value>]...\n\nVerbs:\n"
            ),
            "{tls}"
        );
        let (_, cmds) = describe::groups(reg)
            .into_iter()
            .find(|(g, _)| g == "tls")
            .expect("tls");
        let names: Vec<&str> = cmds.iter().map(|c| c.name()).collect();
        assert_eq!(
            names,
            [
                "tls.passthrough.list",
                "tls.passthrough.add",
                "tls.passthrough.remove"
            ]
        );
        let lefts: Vec<String> = rendered_rows(&block_lines(&tls, "Verbs:"))
            .into_iter()
            .map(|(left, _)| left)
            .collect();
        assert_eq!(
            lefts,
            [
                "passthrough list",
                "passthrough add --host <host>",
                "passthrough remove --host <host>",
            ]
        );
        let examples: Vec<String> = cmds
            .iter()
            .map(|c| format!("  $ {}", examples_for(c.name())[0]))
            .collect();
        assert_eq!(block_lines(&tls, "Examples:"), examples);
        assert!(
            tls.ends_with(&format!("{}\n", examples[2])),
            "no footer: {tls}"
        );
        for name in ["capture", "config", "request"] {
            let (_, cmds) = describe::groups(reg)
                .into_iter()
                .find(|(g, _)| g == name)
                .unwrap_or_else(|| panic!("{name} is a group"));
            assert_eq!(cmds.len(), 1, "{name} has one verb: {:?}", cmds.len());
            let out = render(
                &piped_utf8(),
                &group(reg, name).unwrap_or_else(|| panic!("{name}")),
            );
            assert!(
                out.contains(&format!("\nVerbs:\n  {}", verb_row(cmds[0].as_ref()))),
                "{out}"
            );
            let example = examples_for(cmds[0].name())[0];
            assert!(
                out.ends_with(&format!("\nExamples:\n  $ {example}\n")),
                "{out}"
            );
        }
    }

    /// Under the ASCII glyph set a verb page's description, its flag
    /// descriptions, the group row and the group title follow spec T1: `·`
    /// → `-`, `…` → `...`, ` — ` → ` - ` (plan C41); a UTF-8 pipe keeps them.
    #[test]
    fn verb_and_group_pages_asciify_under_ascii_caps() {
        struct Dotty;
        impl Command for Dotty {
            fn name(&self) -> &str {
                "zzz.dot"
            }
            fn schema(&self) -> ParamSchema {
                ParamSchema {
                    description: "Join a · b … c. Then more.".into(),
                    params: vec![aitm_core::ParamDef {
                        name: "mode".into(),
                        ty: TypeDesc::Str,
                        required: false,
                        description: "one · two … three".into(),
                    }],
                    result: TypeDesc::Bool,
                }
            }
            fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
                anyhow::bail!("zzz.dot is schema-only")
            }
        }
        let mut registry = Registry::new();
        registry.add_command(Arc::new(Dotty));
        let verb_page = verb(registry.command("zzz.dot").expect("registered").as_ref());
        assert_eq!(
            render(&Caps::plain(), &verb_page),
            "Join a - b ... c. Then more.\n\
             \n\
             Usage:\n\
             \x20 aitm zzz dot [--mode <mode>]\n\
             \n\
             Flags:\n\
             \x20 --mode <string>           one - two ... three\n\
             \n\
             Examples:\n\
             \x20 $ aitm zzz dot [--mode <mode>]\n"
        );
        assert!(render(&piped_utf8(), &verb_page).starts_with("Join a · b … c. Then more.\n"));
        let group_page = group(&registry, "zzz").expect("zzz is a group");
        assert_eq!(
            render(&Caps::plain(), &group_page),
            "aitm zzz - (no description)\n\
             \n\
             Usage:\n\
             \x20 aitm zzz <verb> [--flag <value>]...\n\
             \n\
             Verbs:\n\
             \x20 dot                       Join a - b ... c.\n"
        );
        assert!(render(&piped_utf8(), &group_page).starts_with("aitm zzz — (no description)\n"));
    }

    /// AC-W2-2 in-process over the widest registry (the catalogue and
    /// `l4.enabled`: 19 groups; the command count is pinned once, in
    /// `tests/describe_registry.rs`): every group page opens with
    /// its title and usage form and has one row per verb — `verb_row` and the
    /// first sentence — and an example; every verb page opens with its
    /// description, has `Usage: aitm <spaced>`, a `Flags:` row per parameter
    /// with the type word and ` [required]` exactly when required, at least
    /// one example that names the verb, no escape byte, and nothing but an
    /// example line wider than 80 columns.
    #[test]
    fn every_group_and_verb_page_renders_with_the_expected_shape() {
        let described = registry_with_l4("sweep", CATALOGUE_ENV);
        let reg = &described.registry;
        let groups = describe::groups(reg);
        assert_eq!(groups.len(), 19);
        let mut verbs_seen = 0;
        for (name, cmds) in &groups {
            let group_page = group(reg, name).unwrap_or_else(|| panic!("{name}"));
            assert_eq!(
                group_page.usage,
                vec![format!("aitm {name} <verb> [--flag <value>]...")]
            );
            let Some(Block::Section(verbs)) = group_page.blocks.first() else {
                panic!("{name}: the first block is the Verbs: section")
            };
            assert_eq!(verbs.heading, "Verbs:");
            assert_eq!(verbs.rows.len(), cmds.len(), "{name}");
            for (row, cmd) in verbs.rows.iter().zip(cmds) {
                assert_eq!(row.left, verb_row(cmd.as_ref()), "{}", cmd.name());
                assert_eq!(
                    row.right,
                    first_sentence(&cmd.schema().description),
                    "{}",
                    cmd.name()
                );
            }
            let out = render(&piped_utf8(), &group_page);
            assert!(out.starts_with(&format!("aitm {name} — ")), "{out}");
            assert!(out.contains("\nExamples:\n  $ aitm "), "{name}: {out}");
            assert!(!out.as_bytes().contains(&0x1b), "{name}");
            for cmd in cmds {
                verbs_seen += 1;
                let schema = cmd.schema();
                let spaced_name = spaced(cmd.name());
                let verb_page = verb(cmd.as_ref());
                assert_eq!(verb_page.title, "", "{}", cmd.name());
                assert_eq!(verb_page.about, vec![schema.description.clone()]);
                assert_eq!(verb_page.usage, vec![usage_form(cmd.as_ref())]);
                let flags = verb_page.blocks.iter().find_map(|block| match block {
                    Block::Section(section) if section.heading == "Flags:" => Some(section),
                    _ => None,
                });
                match flags {
                    Some(flags) => {
                        assert_eq!(flags.rows.len(), schema.params.len(), "{}", cmd.name());
                        for (row, def) in flags.rows.iter().zip(&schema.params) {
                            assert_eq!(
                                row.left,
                                format!("--{} <{}>", def.name, type_hint(&def.ty)),
                                "{}",
                                cmd.name()
                            );
                            assert!(row.right.starts_with(&def.description));
                            assert_eq!(
                                row.right.ends_with(" [required]"),
                                def.required,
                                "{}: --{}",
                                cmd.name(),
                                def.name
                            );
                        }
                    }
                    None => assert!(schema.params.is_empty(), "{}", cmd.name()),
                }
                let out = render(&piped_utf8(), &verb_page);
                assert!(
                    out.contains(&format!("\nUsage:\n  aitm {spaced_name}")),
                    "{}: {out}",
                    cmd.name()
                );
                assert!(
                    out.contains(&format!("\nExamples:\n  $ aitm {spaced_name}")),
                    "{}: {out}",
                    cmd.name()
                );
                assert!(!out.as_bytes().contains(&0x1b), "{}", cmd.name());
                for line in out.lines().filter(|l| !l.starts_with("  $ ")) {
                    assert!(text::width(line) <= 80, "{}: {line:?}", cmd.name());
                }
            }
        }
        assert_eq!(verbs_seen, reg.commands().count());
    }
}
