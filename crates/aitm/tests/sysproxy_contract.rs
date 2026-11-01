//! Tester (stage 5), SP-AC17 over the REAL assembly (`build_proxy`, no
//! injected engine): the three `proxy.system.*` verbs are registered with
//! the spec's sensitivities, `set` takes exactly one optional
//! `bypass: Array(Str)`, MCP `tools/list` exposes that schema, and the TUI's
//! `CORE_TOOLS` lists the three names. Detection runs no command (plan C2),
//! so building the real engine here touches nothing on the host.
//!
//! Spec: docs/superpowers/specs/2026-10-31-system-proxy-automation-design.md
//! Plan: docs/superpowers/plans/2026-10-31-system-proxy-automation-plan.md (Tasks 8, 9, 11)

use std::time::SystemTime;

use aitm::wire::build_proxy;
use aitm_core::{Config, McpTransport, Sensitivity, TypeDesc};
use aitm_mcp::McpServer;
use serde_json::{json, Value};

const VERBS: [&str; 3] = [
    "proxy.system.status",
    "proxy.system.set",
    "proxy.system.unset",
];

fn config(tag: &str) -> Config {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut cfg = Config::default();
    cfg.ca.dir = std::env::temp_dir().join(format!("aitm-sysproxy-contract-{tag}-{nanos}"));
    cfg
}

fn tools_list(server: &McpServer) -> Vec<Value> {
    let req = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}});
    let resp = server.handle(&req.to_string()).expect("a response");
    let resp: Value = serde_json::from_str(&resp).expect("response is JSON");
    resp["result"]["tools"]
        .as_array()
        .expect("tools array")
        .clone()
}

fn tool<'a>(tools: &'a [Value], name: &str) -> &'a Value {
    tools
        .iter()
        .find(|t| t["name"] == name)
        .unwrap_or_else(|| panic!("{name} in tools/list"))
}

#[test]
fn proxy_system_verbs_over_the_real_assembly() {
    let cfg = config("verbs");
    let proxy = build_proxy(&cfg).expect("build proxy");
    let reg = proxy.registry();

    let status = reg
        .command("proxy.system.status")
        .expect("status registered");
    assert_eq!(status.sensitivity(), Sensitivity::Read);
    assert!(status.schema().params.is_empty());

    let set = reg.command("proxy.system.set").expect("set registered");
    assert_eq!(set.sensitivity(), Sensitivity::Sensitive);
    let schema = set.schema();
    assert_eq!(schema.params.len(), 1, "{:?}", schema.params);
    assert_eq!(schema.params[0].name, "bypass");
    assert!(!schema.params[0].required);
    assert!(
        matches!(&schema.params[0].ty, TypeDesc::Array(inner) if matches!(**inner, TypeDesc::Str)),
        "bypass is Array(Str)"
    );

    let unset = reg.command("proxy.system.unset").expect("unset registered");
    assert_eq!(unset.sensitivity(), Sensitivity::Sensitive);
    assert!(unset.schema().params.is_empty());

    // MCP tools/list: one optional `bypass` array-of-string property, no
    // required list, and the three names present exactly once each.
    let server = McpServer::new(proxy.registry_arc(), McpTransport::Stdio);
    let tools = tools_list(&server);
    for name in VERBS {
        assert_eq!(
            tools.iter().filter(|t| t["name"] == name).count(),
            1,
            "{name} listed once"
        );
    }
    let set_tool = tool(&tools, "proxy.system.set");
    let input = &set_tool["inputSchema"];
    assert_eq!(input["type"], "object", "{input}");
    let props = input["properties"].as_object().expect("properties object");
    assert_eq!(props.keys().collect::<Vec<_>>(), vec!["bypass"], "{input}");
    assert_eq!(props["bypass"]["type"], "array", "{input}");
    assert_eq!(props["bypass"]["items"]["type"], "string", "{input}");
    let required = input.get("required").and_then(Value::as_array);
    assert!(
        required.is_none_or(|r| r.is_empty()),
        "bypass is optional: {input}"
    );
    for name in ["proxy.system.status", "proxy.system.unset"] {
        let t = tool(&tools, name);
        let props = t["inputSchema"]["properties"].as_object();
        assert!(
            props.is_none_or(|p| p.is_empty()),
            "{name} takes no params: {t}"
        );
    }

    // The TUI's pin names the three verbs.
    for name in VERBS {
        assert!(
            aitm_tui::CORE_TOOLS.contains(&name),
            "CORE_TOOLS lists {name}"
        );
    }
    let _ = std::fs::remove_dir_all(&cfg.ca.dir);
}
