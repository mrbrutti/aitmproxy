//! The static help text (plan Task 10; C44–C46): the 19 group purposes and
//! footers, the examples table keyed by dotted command name and by group
//! name, and the top page's mode, option, example and "learn more" rows. A
//! group without an entry renders `(no description)` and fails the catalogue
//! pin, so a new group cannot ship without a purpose.
//!
//! Nothing here is computed: the pages ([`crate::help::pages`]) join this text
//! with the schema-only registry ([`crate::describe`]), so the help path still
//! creates nothing and boots nothing (plan rule 12).

use aitm_core::NOTHING_DECRYPTED_ADVICE;

/// The top page's tagline, after `aitm <version> — `.
pub const TAGLINE: &str = "intercepting proxy for authorized security testing";

/// What a group page is titled with and closes with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupInfo {
    /// The group: the first dotted segment of its commands' names.
    pub name: &'static str,
    /// The purpose, as the top page's `Groups:` row and the group page's title
    /// (`aitm <group> — <purpose>`) print it: a lowercase clause with no
    /// trailing period (plan rule 14).
    pub purpose: &'static str,
    /// The sentence the group page closes with. A sentence the core composes
    /// is used verbatim, never re-cased or re-punctuated (plan rule 14).
    pub footer: Option<&'static str>,
}

/// The 19 groups of plan mock-up M-W2-1, alphabetical (plan C50).
pub const GROUPS: &[GroupInfo] = &[
    GroupInfo {
        name: "agent",
        purpose: "agent policy, approvals and the activity log",
        footer: None,
    },
    GroupInfo {
        name: "browser",
        purpose: "drive the embedded browser",
        footer: None,
    },
    GroupInfo {
        name: "ca",
        purpose: "the root CA: export, status, install, uninstall",
        footer: Some("The embedded browser trusts this CA on its own (--ca-cert); install it for other TLS clients."),
    },
    GroupInfo {
        name: "capture",
        purpose: "the macOS capture extension's status",
        footer: None,
    },
    GroupInfo {
        name: "check",
        purpose: "active checks that confirm one finding at a URL",
        footer: Some("Active checks send requests to the target; run them only against hosts you are authorized to test."),
    },
    GroupInfo {
        name: "config",
        purpose: "the running configuration, redacted",
        footer: None,
    },
    GroupInfo {
        name: "findings",
        purpose: "the persistent findings store",
        footer: None,
    },
    GroupInfo {
        name: "flow",
        purpose: "captured flows: list, inspect, intercept, replay",
        footer: None,
    },
    GroupInfo {
        name: "l4",
        purpose: "raw packet recon, probes and capture (opt-in)",
        footer: Some("Most l4 verbs need l4.enabled in the config and capture privilege; recon and the probes are bundled scripts."),
    },
    GroupInfo {
        name: "map",
        purpose: "Map Local and Map Remote rules",
        footer: None,
    },
    GroupInfo {
        name: "poc",
        purpose: "reproducible proofs of concept",
        footer: None,
    },
    GroupInfo {
        name: "proxy",
        purpose: "proxy state, pause/resume and the system proxy",
        footer: None,
    },
    GroupInfo {
        name: "request",
        purpose: "craft and send a request through the proxy",
        footer: None,
    },
    GroupInfo {
        name: "scan",
        purpose: "discovery, passive checks and the findings report",
        footer: None,
    },
    GroupInfo {
        name: "scope",
        purpose: "which hosts are decrypted",
        footer: Some(NOTHING_DECRYPTED_ADVICE),
    },
    GroupInfo {
        name: "script",
        purpose: "the Rhai detection scripts",
        footer: None,
    },
    GroupInfo {
        name: "session",
        purpose: "save and load the flow store",
        footer: None,
    },
    GroupInfo {
        name: "tls",
        purpose: "TLS passthrough: hosts tunnelled, not decrypted",
        footer: None,
    },
    GroupInfo {
        name: "ws",
        purpose: "WebSocket frame interception and injection",
        footer: None,
    },
];

/// The catalogue entry for a group, if it has one.
pub fn group_info(name: &str) -> Option<&'static GroupInfo> {
    GROUPS.iter().find(|group| group.name == name)
}

/// The examples, keyed by dotted command name (`scope.add`) and by group name
/// (`scope`), sorted by key (plan C45).
pub const EXAMPLES: &[(&str, &[&str])] = &[
    ("agent.activity", &[
        "aitm agent activity --limit 50",
    ]),
    ("agent.approve", &[
        "aitm agent approve --request_id ar-7f2c --allow true",
    ]),
    ("agent.set", &[
        "aitm agent set --policy ask",
    ]),
    ("agent.status", &[
        "aitm agent status",
    ]),
    ("browser.click", &[
        "aitm browser click --selector 'button[type=submit]'",
    ]),
    ("browser.confine", &[
        "aitm browser confine --on true",
    ]),
    ("browser.eval", &[
        "aitm browser eval --expr 'document.title'",
    ]),
    ("browser.get_dom", &[
        "aitm browser get_dom",
    ]),
    ("browser.navigate", &[
        "aitm browser navigate --url https://app.example.test/login",
    ]),
    ("browser.screenshot", &[
        "aitm browser screenshot",
    ]),
    ("browser.type", &[
        "aitm browser type --selector '#user' --text analyst",
    ]),
    ("ca.export", &[
        "aitm ca export --format pem --out ~/aitm-ca.pem",
    ]),
    ("ca.install", &[
        "aitm ca install",
        "aitm ca install --yes",
    ]),
    ("ca.status", &[
        "aitm ca status",
    ]),
    ("ca.uninstall", &[
        "aitm ca uninstall --dry_run true",
        "aitm ca uninstall --scope user",
    ]),
    ("capture.status", &[
        "aitm capture status",
    ]),
    ("check.cmdi", &[
        "aitm check cmdi --args '{\"url\":\"https://app.example.test/\",\"param\":\"host\"}'",
    ]),
    ("check.cors", &[
        "aitm check cors --args '{\"url\":\"https://app.example.test/api/me\"}'",
    ]),
    ("check.crlf", &[
        "aitm check crlf --args '{\"url\":\"https://app.example.test/\",\"param\":\"lang\"}'",
    ]),
    ("check.headers", &[
        "aitm check headers --args '{\"url\":\"https://app.example.test/\"}'",
    ]),
    ("check.ldapi", &[
        "aitm check ldapi --args '{\"url\":\"https://app.example.test/\",\"param\":\"user\"}'",
    ]),
    ("check.methods", &[
        "aitm check methods --args '{\"url\":\"https://app.example.test/api/me\"}'",
    ]),
    ("check.nosqli", &[
        "aitm check nosqli --args '{\"url\":\"https://app.example.test/\",\"param\":\"user\"}'",
    ]),
    ("check.open_redirect", &[
        "aitm check open_redirect --args '{\"url\":\"https://app.example.test/\",\"param\":\"next\"}'",
    ]),
    ("check.path_traversal", &[
        "aitm check path_traversal --args '{\"url\":\"https://app.example.test/\",\"param\":\"file\"}'",
    ]),
    ("check.paths", &[
        "aitm check paths --args '{\"base\":\"https://app.example.test/\"}'",
    ]),
    ("check.sqli", &[
        "aitm check sqli --args '{\"url\":\"https://app.example.test/\",\"param\":\"id\"}'",
    ]),
    ("check.ssrf", &[
        "aitm check ssrf --args '{\"url\":\"https://app.example.test/\",\"param\":\"target\"}'",
    ]),
    ("check.ssti", &[
        "aitm check ssti --args '{\"url\":\"https://app.example.test/\",\"param\":\"name\"}'",
    ]),
    ("check.xss", &[
        "aitm check xss --args '{\"url\":\"https://app.example.test/search\",\"param\":\"q\"}'",
    ]),
    ("check.xxe", &[
        "aitm check xxe --args '{\"url\":\"https://app.example.test/api/xml\"}'",
    ]),
    ("config.get", &[
        "aitm config get",
    ]),
    ("findings.get", &[
        "aitm findings get --id f-3a91c0",
    ]),
    ("findings.list", &[
        "aitm findings list --filter '{\"severity\":\"high\"}'",
    ]),
    ("findings.record", &[
        "aitm findings record --title XSS --class xss --severity high --target https://app.example.test/search --poc_ref ~/poc/xss.yaml",
    ]),
    ("findings.remove", &[
        "aitm findings remove --id f-3a91c0",
    ]),
    ("flow.clear", &[
        "aitm flow clear",
    ]),
    ("flow.comment", &[
        "aitm flow comment --id 3f2a9c1e-7b10-4c4d-9e21-04ad5b6c7d8e --text review",
    ]),
    ("flow.detail", &[
        "aitm flow detail --id 3f2a9c1e-7b10-4c4d-9e21-04ad5b6c7d8e",
        "aitm flow detail --id 3f2a9c1e-7b10-4c4d-9e21-04ad5b6c7d8e --body none",
    ]),
    ("flow.export", &[
        "aitm flow export --format har --path ~/aitm/flows.har",
    ]),
    ("flow.get", &[
        "aitm flow get --id 3f2a9c1e-7b10-4c4d-9e21-04ad5b6c7d8e",
    ]),
    ("flow.import", &[
        "aitm flow import --format har --path ~/aitm/flows.har",
    ]),
    ("flow.intercept", &[
        "aitm flow intercept --enabled true",
        "aitm flow intercept --enabled false",
    ]),
    ("flow.kill", &[
        "aitm flow kill --id 3f2a9c1e-7b10-4c4d-9e21-04ad5b6c7d8e --mode 503",
    ]),
    ("flow.list", &[
        "aitm flow list",
    ]),
    ("flow.mark", &[
        "aitm flow mark --id 3f2a9c1e-7b10-4c4d-9e21-04ad5b6c7d8e --marks '[\"red\"]'",
    ]),
    ("flow.mutate", &[
        "aitm flow mutate --id 3f2a9c1e-7b10-4c4d-9e21-04ad5b6c7d8e --edits '{\"method\":\"POST\"}'",
    ]),
    ("flow.replay", &[
        "aitm flow replay --id 3f2a9c1e-7b10-4c4d-9e21-04ad5b6c7d8e",
    ]),
    ("flow.resume", &[
        "aitm flow resume --id 3f2a9c1e-7b10-4c4d-9e21-04ad5b6c7d8e",
    ]),
    ("flow.subscribe", &[
        "aitm flow subscribe --filter '{\"host\":\"app.example.test\"}'",
    ]),
    ("flow.table", &[
        "aitm flow table",
    ]),
    ("flow.unsubscribe", &[
        "aitm flow unsubscribe --sub_id 1",
    ]),
    ("l4.agent.set", &[
        "aitm l4 agent set --capability capture --allowed false",
    ]),
    ("l4.agent.status", &[
        "aitm l4 agent status",
    ]),
    ("l4.capture.start", &[
        "aitm l4 capture start --interface lo0 --direction outbound",
    ]),
    ("l4.capture.status", &[
        "aitm l4 capture status",
    ]),
    ("l4.capture.stop", &[
        "aitm l4 capture stop --id c-1",
    ]),
    ("l4.craft", &[
        "aitm l4 craft --spec '{\"layers\":[{\"ipv4\":{\"dst\":\"127.0.0.1\"}}]}'",
    ]),
    ("l4.flow.get", &[
        "aitm l4 flow get --id c-1 --offset 0 --limit 64",
    ]),
    ("l4.flow.list", &[
        "aitm l4 flow list",
    ]),
    ("l4.inject", &[
        "aitm l4 inject --spec '{\"layers\":[{\"udp\":{\"dport\":53}}]}' --dst 127.0.0.1 --interface lo0",
    ]),
    ("l4.intercept.drop", &[
        "aitm l4 intercept drop --id p-1",
    ]),
    ("l4.intercept.forward", &[
        "aitm l4 intercept forward --id p-1",
    ]),
    ("l4.intercept.list", &[
        "aitm l4 intercept list --flow i-1",
    ]),
    ("l4.intercept.mutate", &[
        "aitm l4 intercept mutate --id p-1 --bytes 4500002c",
    ]),
    ("l4.intercept.revert", &[
        "aitm l4 intercept revert --id p-1",
    ]),
    ("l4.intercept.start", &[
        "aitm l4 intercept start --interface eth0 --queue_num 0",
    ]),
    ("l4.intercept.status", &[
        "aitm l4 intercept status",
    ]),
    ("l4.intercept.stop", &[
        "aitm l4 intercept stop --flow i-1",
    ]),
    ("l4.interfaces", &[
        "aitm l4 interfaces",
    ]),
    ("l4.recon", &[
        "aitm l4 recon",
    ]),
    ("l4.scope.add", &[
        "aitm l4 scope add --cidr 127.0.0.1/32 --interface lo0 --direction outbound --capability capture",
    ]),
    ("l4.scope.list", &[
        "aitm l4 scope list",
    ]),
    ("l4.scope.remove", &[
        "aitm l4 scope remove --id s-1",
    ]),
    ("l4.send_recv", &[
        "aitm l4 send_recv --spec '{\"layers\":[{\"udp\":{\"dport\":53}}]}' --dst 127.0.0.1 --interface lo0",
    ]),
    ("l4.tcp_probe", &[
        "aitm l4 tcp_probe --args '{\"dst\":\"127.0.0.1\",\"port\":443,\"interface\":\"lo0\"}'",
    ]),
    ("l4.udp_probe", &[
        "aitm l4 udp_probe --args '{\"dst\":\"127.0.0.1\",\"port\":53,\"interface\":\"lo0\"}'",
    ]),
    ("map.add", &[
        "aitm map add --kind remote --condition '{\"url\":{\"wildcard\":\"*/api/*\"}}' --action '{\"to\":{\"authority\":\"stage.example.test\"}}'",
    ]),
    ("map.list", &[
        "aitm map list",
    ]),
    ("map.remove", &[
        "aitm map remove --id m-1",
    ]),
    ("poc.artifact", &[
        "aitm poc artifact --path ~/aitm/poc/out/xss-search.png",
    ]),
    ("poc.build", &[
        "aitm poc build --flow_id 3f2a9c1e-7b10-4c4d-9e21-04ad5b6c7d8e --param q",
    ]),
    ("poc.get", &[
        "aitm poc get --poc_path ~/aitm/poc/xss-search.yaml",
    ]),
    ("poc.list", &[
        "aitm poc list",
    ]),
    ("poc.run", &[
        "aitm poc run --poc_path ~/aitm/poc/xss-search.yaml --target https://app.example.test",
    ]),
    ("proxy.pause", &[
        "aitm proxy pause",
    ]),
    ("proxy.resume", &[
        "aitm proxy resume",
    ]),
    ("proxy.status", &[
        "aitm proxy status",
    ]),
    ("proxy.system.set", &[
        "aitm proxy system set",
    ]),
    ("proxy.system.status", &[
        "aitm proxy system status",
    ]),
    ("proxy.system.unset", &[
        "aitm proxy system unset",
    ]),
    ("request.send", &[
        "aitm request send --authority app.example.test --path /login",
    ]),
    ("scan.discover", &[
        "aitm scan discover --target https://app.example.test/ --max_pages 50",
    ]),
    ("scan.passive", &[
        "aitm scan passive --target https://app.example.test",
    ]),
    ("scan.report", &[
        "aitm scan report --target https://app.example.test",
    ]),
    ("scope", &[
        "aitm scope add --host app.example.test",
        "aitm scope add --host '*.example.test'",
        "aitm scope list",
    ]),
    ("scope.add", &[
        "aitm scope add --host app.example.test",
        "aitm scope add --host '*.example.test'",
    ]),
    ("scope.list", &[
        "aitm scope list",
    ]),
    ("scope.remove", &[
        "aitm scope remove --host app.example.test",
    ]),
    ("script.disable", &[
        "aitm script disable --name login",
    ]),
    ("script.enable", &[
        "aitm script enable --name login",
    ]),
    ("script.findings", &[
        "aitm script findings --limit 20",
    ]),
    ("script.list", &[
        "aitm script list",
    ]),
    ("script.reload", &[
        "aitm script reload --name login",
    ]),
    ("script.save", &[
        "aitm script save --name login --source 'fn on_request(f) { }'",
    ]),
    ("script.validate", &[
        "aitm script validate --path ~/aitm/scripts/login.rhai",
    ]),
    ("session.load", &[
        "aitm session load --path ~/aitm/sessions/today.json",
    ]),
    ("session.save", &[
        "aitm session save --path ~/aitm/sessions/today.json",
    ]),
    ("tls.passthrough.add", &[
        "aitm tls passthrough add --host '*.cdn.example.test'",
    ]),
    ("tls.passthrough.list", &[
        "aitm tls passthrough list",
    ]),
    ("tls.passthrough.remove", &[
        "aitm tls passthrough remove --host app.example.test",
    ]),
    ("ws.frame", &[
        "aitm ws frame --id 3f2a9c1e-7b10-4c4d-9e21-04ad5b6c7d8e --index 0 --action forward",
    ]),
    ("ws.intercept", &[
        "aitm ws intercept --enabled true",
    ]),
    ("ws.send", &[
        "aitm ws send --id 3f2a9c1e-7b10-4c4d-9e21-04ad5b6c7d8e --dir c2s --opcode text --data ping",
    ]),
];

/// The examples for a dotted command name or a group name; empty when the
/// catalogue has none (the verb page then falls back to its usage form, and
/// the catalogue pin fails, so the fallback never ships — plan C45).
pub fn examples_for(key: &str) -> &'static [&'static str] {
    EXAMPLES
        .iter()
        .find(|(entry, _)| *entry == key)
        .map(|(_, lines)| *lines)
        .unwrap_or(&[])
}

/// The five `Usage:` rows of the top page.
pub const MODE_ROWS: &[(&str, &str)] = &[
    ("aitm", "run the proxy with the MCP agent transport"),
    (
        "aitm web [options]",
        "run the proxy and the web operator UI",
    ),
    ("aitm tui", "run the proxy and the terminal operator UI"),
    (
        "aitm <group> <verb> [--flag <value>]...",
        "run one command and exit",
    ),
    (
        "aitm operator-token generate [--force]",
        "write a new operator token into the config file",
    ),
];

/// The eight `Options:` rows of the top page.
pub const OPTION_ROWS: &[(&str, &str)] = &[
    ("--config <path>", "config file (env AITM_CONFIG)"),
    ("--script <path>", "load an extra Rhai script (repeatable)"),
    (
        "--yes",
        "answer a verb's confirmation prompt without asking",
    ),
    ("-v, -vv", "show INFO / DEBUG tracing on stderr"),
    ("-q", "errors only"),
    (
        "--color <auto|always|never>",
        "force or disable colour (NO_COLOR, CLICOLOR_FORCE)",
    ),
    ("--version, -V", "print the version and exit"),
    ("--help, -h", "print this help"),
];

/// The top page's `Examples:` lines (the renderer adds the `$ ` prompt).
pub const TOP_EXAMPLES: &[&str] = &[
    "aitm",
    "aitm web --no-open",
    "aitm scope add --host app.example.test",
    "aitm flow table",
];

/// The top page's `Learn more:` rows.
pub const LEARN_MORE_ROWS: &[(&str, &str)] = &[
    ("aitm <group>", "a group's verbs (aitm scope)"),
    (
        "aitm <group> <verb> --help",
        "a verb's flags and examples (aitm scope add --help)",
    ),
    ("aitm web --help", "the web UI's options"),
];

/// The top page's closing lines.
pub const TOP_FOOTER: &[&str] = &[
    "Nothing is decrypted until a host is in Scope.  aitm scope add --host <host>",
    "Trust the CA:  aitm ca install",
];

/// Compile-time `haystack` starts with `prefix`, over bytes (no crate, const
/// context).
const fn starts_with(haystack: &str, prefix: &str) -> bool {
    let (haystack, prefix) = (haystack.as_bytes(), prefix.as_bytes());
    if haystack.len() < prefix.len() {
        return false;
    }
    let mut i = 0;
    while i < prefix.len() {
        if haystack[i] != prefix[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// [`TOP_FOOTER`]'s first line is the core's sentence plus the next step, so
/// the literal is built with `aitm_core::NOTHING_DECRYPTED_ADVICE` (plan Task
/// 10) and this fails to compile if the core ever re-words it (rule 14: a
/// sentence the core composes is printed verbatim).
const _: () = assert!(starts_with(TOP_FOOTER[0], NOTHING_DECRYPTED_ADVICE));

/// What a group without a catalogue entry renders as.
pub const NO_PURPOSE: &str = "(no description)";

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use aitm_core::{Config, TypeDesc};
    use aitm_plugin_rhai::RhaiConfig;
    use aitm_proto_l4::config::L4Config;
    use aitm_sysproxy::SystemProxyConfig;

    use super::*;
    use crate::config_file::Settings;
    use crate::describe::{self, DescribeInputs, Described};
    use crate::macos_capture::config::MacosCaptureConfig;

    /// The shipped catalogue, reached through the injected env (plan rule 13).
    const BUNDLED: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../scripts/bundled");

    /// The 19 groups of plan mock-up M-W2-1.
    const MOCKUP_GROUPS: [&str; 19] = [
        "agent", "browser", "ca", "capture", "check", "config", "findings", "flow", "l4", "map",
        "poc", "proxy", "request", "scan", "scope", "script", "session", "tls", "ws",
    ];

    /// The width an example may use (plan C45): 76, so the renderer's `  $ `
    /// prefix still fits an 80-column terminal.
    const WIDTH: usize = 76;

    /// The width an example may use when the command's own inputs cannot fit
    /// [`WIDTH`] (plan C45).
    const WIDE: usize = 128;

    /// The schema-only registry with the bundled catalogue and `l4.enabled`:
    /// the widest command set help can show (113 commands, 19 groups). The CA
    /// directory is pointed under the temp dir and never created (rule 12).
    fn catalogue_registry_with_l4() -> Described {
        let mut core = Config::default();
        core.ca.dir = std::env::temp_dir().join(format!(
            "aitm-help-catalog-{}-never-created",
            std::process::id()
        ));
        let settings = Settings {
            core,
            rhai: RhaiConfig::default(),
            l4: L4Config {
                enabled: true,
                ..L4Config::default()
            },
            macos_capture: MacosCaptureConfig::default(),
            system_proxy: SystemProxyConfig::default(),
        };
        let env: BTreeMap<String, String> =
            BTreeMap::from([("AITM_BUNDLED_SCRIPTS".to_string(), BUNDLED.to_string())]);
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

    /// The width budget for one key, **derived from the registry schema**, so
    /// the exemption is never a hand-kept list (plan C45): [`WIDE`] when the
    /// command's own inputs cannot fit [`WIDTH`] — it takes a JSON value
    /// (`Object`/`Map`/`Any`: `dispatch.rs` parses one JSON text per flag, so
    /// the whole object sits on the line) or it has three or more required
    /// flags (`findings.record`, `l4.scope.add`, `ws.frame`, `ws.send`: the
    /// flag names and a 36-character flow id alone pass 76) — else [`WIDTH`].
    fn width_budget(registry: &aitm_core::Registry, key: &str) -> usize {
        let Some(cmd) = registry.command(key) else {
            return WIDTH;
        };
        let schema = cmd.schema();
        let json = schema
            .params
            .iter()
            .any(|p| matches!(p.ty, TypeDesc::Object(_) | TypeDesc::Map(_) | TypeDesc::Any));
        let required = schema.params.iter().filter(|p| p.required).count();
        if json || required >= 3 {
            WIDE
        } else {
            WIDTH
        }
    }

    #[test]
    fn groups_are_alphabetical_unique_and_nineteen() {
        let names: Vec<&str> = GROUPS.iter().map(|group| group.name).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(names, sorted, "GROUPS is alphabetical and distinct");
        assert_eq!(names.len(), 19);
        assert_eq!(names, MOCKUP_GROUPS);

        for group in GROUPS {
            assert!(
                !group.purpose.is_empty() && !group.purpose.ends_with('.'),
                "`{}`: a purpose is a clause with no trailing period (plan rule 14): {:?}",
                group.name,
                group.purpose
            );
        }
        assert_eq!(
            group_info("scope"),
            Some(&GroupInfo {
                name: "scope",
                purpose: "which hosts are decrypted",
                footer: Some(NOTHING_DECRYPTED_ADVICE),
            })
        );
        assert_eq!(
            group_info("ca").and_then(|group| group.footer),
            Some("The embedded browser trusts this CA on its own (--ca-cert); install it for other TLS clients.")
        );
        assert_eq!(
            group_info("check").and_then(|group| group.footer),
            Some("Active checks send requests to the target; run them only against hosts you are authorized to test.")
        );
        assert_eq!(
            group_info("l4").and_then(|group| group.footer),
            Some("Most l4 verbs need l4.enabled in the config and capture privilege; recon and the probes are bundled scripts.")
        );
        let with_footer: Vec<&str> = GROUPS
            .iter()
            .filter(|group| group.footer.is_some())
            .map(|group| group.name)
            .collect();
        assert_eq!(with_footer, ["ca", "check", "l4", "scope"]);
        assert_eq!(group_info("nope"), None);
        assert_eq!(group_info("scope.add"), None, "keyed by group, not by verb");
    }

    #[test]
    fn every_registered_command_and_group_has_a_purpose_and_an_example() {
        let described = catalogue_registry_with_l4();
        let registry = &described.registry;
        let groups = describe::groups(registry);
        let group_names: Vec<&str> = groups.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            group_names, MOCKUP_GROUPS,
            "the registry under test has the 19 groups"
        );
        assert_eq!(
            registry.commands().count(),
            113,
            "the catalogue + l4.enabled registry (plan Task 10)"
        );

        let without_purpose: Vec<&str> = group_names
            .iter()
            .copied()
            .filter(|name| group_info(name).is_none())
            .collect();
        assert!(
            without_purpose.is_empty(),
            "registered groups with no catalogue purpose (they would render as {NO_PURPOSE}): {without_purpose:?}"
        );

        let stale_groups: Vec<&str> = GROUPS
            .iter()
            .map(|group| group.name)
            .filter(|name| !describe::is_group(registry, name))
            .collect();
        assert!(
            stale_groups.is_empty(),
            "GROUPS names that are not a registered group: {stale_groups:?}"
        );

        let without_example: Vec<&str> = registry
            .commands()
            .map(|cmd| cmd.name())
            .filter(|name| examples_for(name).is_empty())
            .collect();
        assert!(
            without_example.is_empty(),
            "registered commands with no example (AC-W2-2): {without_example:?}"
        );

        let unknown_keys: Vec<&str> = EXAMPLES
            .iter()
            .map(|(key, _)| *key)
            .filter(|key| registry.command(key).is_none() && !describe::is_group(registry, key))
            .collect();
        assert!(
            unknown_keys.is_empty(),
            "EXAMPLES keys that are neither a registered command nor a group: {unknown_keys:?}"
        );
    }

    #[test]
    fn every_example_is_a_runnable_aitm_line() {
        let described = catalogue_registry_with_l4();
        assert!(!EXAMPLES.is_empty(), "the examples table is filled");
        for (key, lines) in EXAMPLES {
            assert!(!lines.is_empty(), "`{key}` has an empty example list");
            let budget = width_budget(&described.registry, key);
            for line in *lines {
                assert!(
                    line.starts_with("aitm "),
                    "`{key}`: an example is a runnable aitm line: {line:?}"
                );
                assert!(!line.contains('\n'), "`{key}`: one line: {line:?}");
                assert!(
                    !line.ends_with('.'),
                    "`{key}`: no trailing period: {line:?}"
                );
                assert_eq!(
                    line.trim(),
                    *line,
                    "`{key}`: no surrounding whitespace: {line:?}"
                );
                assert!(
                    line.chars().count() <= budget,
                    "`{key}`: at most {budget} columns, is {}: {line:?}",
                    line.chars().count()
                );
                // The words after `aitm ` begin with the key's dot-segments in
                // order, so an example always names its own command, spaced
                // (`l4 scope add …` for `l4.scope.add`).
                let segments: Vec<&str> = key.split('.').collect();
                let words: Vec<&str> = line.split_whitespace().skip(1).collect();
                assert_eq!(
                    words.get(..segments.len()),
                    Some(segments.as_slice()),
                    "`{key}`: the example names its own command, spaced: {line:?}"
                );
            }
        }
    }

    #[test]
    fn examples_are_sorted_by_key_and_unique() {
        assert!(!EXAMPLES.is_empty(), "the examples table is filled");
        let keys: Vec<&str> = EXAMPLES.iter().map(|(key, _)| *key).collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            keys, sorted,
            "EXAMPLES is sorted by key and has no duplicate key"
        );
        for (key, lines) in EXAMPLES {
            let mut distinct = lines.to_vec();
            distinct.sort_unstable();
            distinct.dedup();
            assert_eq!(
                distinct.len(),
                lines.len(),
                "`{key}` repeats an example: {lines:?}"
            );
        }
        assert_eq!(examples_for("nope"), &[] as &[&str]);
        assert_eq!(
            examples_for("scope"),
            [
                "aitm scope add --host app.example.test",
                "aitm scope add --host '*.example.test'",
                "aitm scope list",
            ],
            "the `scope` group carries the three M-W2-2 lines"
        );
        assert_eq!(
            examples_for("ca.install"),
            ["aitm ca install", "aitm ca install --yes"]
        );
        assert_eq!(
            examples_for("flow.detail"),
            [
                "aitm flow detail --id 3f2a9c1e-7b10-4c4d-9e21-04ad5b6c7d8e",
                "aitm flow detail --id 3f2a9c1e-7b10-4c4d-9e21-04ad5b6c7d8e --body none",
            ]
        );
    }

    #[test]
    fn top_rows_match_the_mockup() {
        assert_eq!(
            TAGLINE,
            "intercepting proxy for authorized security testing"
        );
        assert_eq!(MODE_ROWS.len(), 5);
        assert_eq!(
            MODE_ROWS.get(3).copied(),
            Some((
                "aitm <group> <verb> [--flag <value>]...",
                "run one command and exit"
            ))
        );
        assert_eq!(OPTION_ROWS.len(), 8);
        assert_eq!(
            OPTION_ROWS.get(2).copied(),
            Some((
                "--yes",
                "answer a verb's confirmation prompt without asking"
            ))
        );
        assert_eq!(
            TOP_EXAMPLES,
            [
                "aitm",
                "aitm web --no-open",
                "aitm scope add --host app.example.test",
                "aitm flow table",
            ]
        );
        assert_eq!(LEARN_MORE_ROWS.len(), 3);
        assert_eq!(
            LEARN_MORE_ROWS.first().copied(),
            Some(("aitm <group>", "a group's verbs (aitm scope)"))
        );
        assert_eq!(
            TOP_FOOTER,
            [
                "Nothing is decrypted until a host is in Scope.  aitm scope add --host <host>",
                "Trust the CA:  aitm ca install",
            ]
        );
        assert_eq!(
            TOP_FOOTER.first().copied(),
            Some(format!("{NOTHING_DECRYPTED_ADVICE}  aitm scope add --host <host>").as_str()),
            "the first footer line is the core's sentence verbatim (plan rule 14)"
        );
        assert_eq!(NO_PURPOSE, "(no description)");
        for (left, right) in MODE_ROWS.iter().chain(OPTION_ROWS).chain(LEARN_MORE_ROWS) {
            assert!(
                !right.ends_with('.'),
                "descriptions we compose carry no trailing period (rule 14): {left:?} -> {right:?}"
            );
        }
    }
}
