//! Task 16 / AC-M4-16b: the harness-neutral agent driver surface validator.
//!
//! Two guarantees, no live model in the loop:
//!
//! 1. [`adapters_are_well_formed`] — every adapter config under `agent/` is
//!    well-formed; the Claude `.mcp.json` and the generic `mcp.json` name the
//!    loopback-TCP bus transport and the agent token file; and the portable
//!    `PLAYBOOK.md` references only commands the registry actually serves. The
//!    authoritative tool list is the *live* `tools/list` assembled here (a
//!    checked-in list would silently drift from the real command surface), so a
//!    typo or a hallucinated command in the playbook fails the build.
//! 2. [`no_provider_sdk_in_workspace`] — no `aitm-*` crate depends on an
//!    Anthropic/OpenAI SDK. The adapters only point a harness at the bus; all
//!    intelligence stays in the model, all machinery stays in the tool.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use aitm::wire::{assemble_with_scripts, Features, ScriptWiring};
use aitm_core::{Config, ScopeEntry};
use aitm_findings::FindingsPlugin;
use serde_json::Value as JsonValue;

/// Command namespaces the playbook may reference. A backticked `ns.verb` whose
/// `ns` is one of these is treated as a command reference and must be real; a
/// dotted token in any other namespace (a path like `report.md`, a config key)
/// is ignored.
const COMMAND_NAMESPACES: [&str; 10] = [
    "agent", "browser", "ca", "config", "findings", "flow", "poc", "proxy", "request", "scope",
];

/// The workspace root: `CARGO_MANIFEST_DIR` is `<root>/crates/aitm`.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root is two levels above crates/aitm")
        .to_path_buf()
}

/// The command surface an agent drives: the default wired plugins plus the M4
/// findings store (`findings.*`), which the binary registers among its command
/// providers (`main.rs`). This is the authoritative tool list the playbook is
/// validated against.
fn agent_command_surface() -> BTreeSet<String> {
    let mut cfg = Config::default();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    cfg.ca.dir = std::env::temp_dir().join(format!("aitm-agent-surface-{nanos}"));
    cfg.scope.entries = vec![ScopeEntry {
        host: "ex.test:80".into(),
    }];
    let assembled = assemble_with_scripts(
        &cfg,
        &Features::default(),
        ScriptWiring {
            commands: vec![Box::new(FindingsPlugin::new())],
            ..Default::default()
        },
    )
    .expect("assemble the agent command surface");
    assembled
        .proxy
        .registry_arc()
        .commands()
        .map(|c| c.name().to_string())
        .collect()
}

/// Extract the command references from a playbook: the first word of each inline
/// `code` span that reads as a `namespace.verb` command. Fenced code blocks are
/// skipped (they carry examples, not the contract), and multi-dot tokens (file
/// paths like `findings.index.json`) are not commands.
fn playbook_command_refs(text: &str) -> BTreeSet<String> {
    let mut refs = BTreeSet::new();
    let mut in_fence = false;
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        // Inline code spans are delimited by single backticks: odd segments of a
        // backtick split are inside a span.
        for (i, span) in line.split('`').enumerate() {
            if i % 2 == 0 {
                continue;
            }
            let Some(word) = span.split_whitespace().next() else {
                continue;
            };
            let Some((ns, verb)) = word.split_once('.') else {
                continue;
            };
            if verb.contains('.') {
                continue; // a dotted path, not a command
            }
            if COMMAND_NAMESPACES.contains(&ns)
                && !verb.is_empty()
                && verb.chars().all(|c| c.is_ascii_lowercase() || c == '_')
            {
                refs.insert(word.to_string());
            }
        }
    }
    refs
}

/// Assert an adapter config names the loopback-TCP bus and the agent token file
/// (so an operator can see what it connects to and where the secret comes from).
fn assert_names_bus_and_token(text: &str, path: &Path) {
    let lower = text.to_ascii_lowercase();
    assert!(
        text.contains("127.0.0.1") || lower.contains("loopback"),
        "{} must name the loopback-TCP bus (127.0.0.1)",
        path.display()
    );
    assert!(
        text.contains("token-file") || text.contains("token_file") || text.contains(".token"),
        "{} must name the agent token file",
        path.display()
    );
}

#[test]
fn adapters_are_well_formed() {
    let agent = repo_root().join("agent");

    // (1) The Claude plugin's MCP wiring parses as JSON and names bus + token.
    let claude_mcp = agent.join("claude/.mcp.json");
    let claude_text = std::fs::read_to_string(&claude_mcp)
        .unwrap_or_else(|e| panic!("read {}: {e}", claude_mcp.display()));
    let claude_json: JsonValue = serde_json::from_str(&claude_text)
        .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", claude_mcp.display()));
    assert!(
        claude_json.get("mcpServers").is_some(),
        "{} must define `mcpServers`",
        claude_mcp.display()
    );
    assert_names_bus_and_token(&claude_text, &claude_mcp);

    // (2) The generic MCP-client config parses as JSON and names bus + token.
    let generic_cfg = agent.join("generic/mcp.json");
    let generic_text = std::fs::read_to_string(&generic_cfg)
        .unwrap_or_else(|e| panic!("read {}: {e}", generic_cfg.display()));
    let _: JsonValue = serde_json::from_str(&generic_text)
        .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", generic_cfg.display()));
    assert_names_bus_and_token(&generic_text, &generic_cfg);

    // (3) The OpenAI/Codex adapter config is a Codex `[mcp_servers.*]` block.
    // It is TOML; parsed structurally here to avoid pulling a TOML dependency
    // into the workspace for one assertion.
    let openai_cfg = agent.join("openai/config.toml");
    let openai_text = std::fs::read_to_string(&openai_cfg)
        .unwrap_or_else(|e| panic!("read {}: {e}", openai_cfg.display()));
    assert!(
        openai_text.contains("[mcp_servers"),
        "{} must declare an `[mcp_servers.*]` table",
        openai_cfg.display()
    );
    assert_names_bus_and_token(&openai_text, &openai_cfg);

    // (4) The portable playbook references only commands the bus serves.
    let playbook =
        std::fs::read_to_string(agent.join("PLAYBOOK.md")).expect("read agent/PLAYBOOK.md");
    let surface = agent_command_surface();
    let refs = playbook_command_refs(&playbook);
    assert!(
        !refs.is_empty(),
        "the playbook must reference the bus commands it drives"
    );
    let unknown: Vec<&String> = refs.iter().filter(|c| !surface.contains(*c)).collect();
    assert!(
        unknown.is_empty(),
        "PLAYBOOK.md references commands the bus does not serve: {unknown:?}\n\
         served surface: {surface:?}"
    );

    // The spine of the observe -> reason -> act -> reproduce -> record -> report
    // loop must actually be documented (not just free of typos).
    for required in [
        "flow.subscribe",
        "flow.detail",
        "poc.build",
        "poc.run",
        "findings.record",
    ] {
        assert!(
            refs.contains(required),
            "the playbook must document `{required}`"
        );
    }
}

/// Dependency-section lines of a Cargo manifest, with comments and table
/// headers dropped. Catches both `name = ...` keys and `package = "..."`
/// renames, so a provider SDK cannot hide behind an alias.
fn dependency_lines(manifest: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut in_deps = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_deps = trimmed.contains("dependencies");
            continue;
        }
        if !in_deps || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        lines.push(trimmed.to_string());
    }
    lines
}

#[test]
fn no_provider_sdk_in_workspace() {
    let root = repo_root();
    let mut manifests = vec![root.join("Cargo.toml")];
    for entry in std::fs::read_dir(root.join("crates")).expect("read crates dir") {
        let manifest = entry.expect("dir entry").path().join("Cargo.toml");
        if manifest.is_file() {
            manifests.push(manifest);
        }
    }

    // Provider SDK crate names (and their common aliases) an aitm crate must
    // never depend on. The adapters point a harness at the bus; they ship no SDK.
    const BANNED: [&str; 2] = ["openai", "anthropic"];
    let mut offenders = Vec::new();
    for manifest in &manifests {
        let text = std::fs::read_to_string(manifest)
            .unwrap_or_else(|e| panic!("read {}: {e}", manifest.display()));
        for line in dependency_lines(&text) {
            let lower = line.to_ascii_lowercase();
            if BANNED.iter().any(|b| lower.contains(b)) {
                offenders.push(format!("{}: {line}", manifest.display()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "no aitm crate may depend on a provider SDK; found:\n{}",
        offenders.join("\n")
    );
}
