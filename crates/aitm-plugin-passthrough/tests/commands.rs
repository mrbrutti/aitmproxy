//! Task 10 — the `tls.passthrough.*` commands as a frontend sees them:
//! `PassthroughPlugin` registered in a `Registry`, invoked through a
//! `CommandHost` that declares its `Frontend`, against the shared list.
//!
//! AC-F11.2: an agent (`Frontend::Mcp`) is refused `add`/`remove` when
//! `allow_agent_passthrough` is false; the human CLI is allowed; `list` reflects
//! adds and removes.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use aitm_core::{
    CommandHost, Frontend, HttpFlow, HttpRequest, MemFlowStore, Params, ProxyClient, Registry,
    StdGuard, Value,
};
use aitm_plugin_passthrough::PassthroughPlugin;

/// A `ProxyClient` stub: `CommandHost` needs one, but no `tls.passthrough.*`
/// command calls it.
struct StubClient;

impl ProxyClient for StubClient {
    fn send(
        &self,
        _req: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<HttpFlow>> + Send + '_>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

/// The plugin, its registry, and the doubles `CommandHost` requires.
struct Harness {
    reg: Registry,
    store: MemFlowStore,
    guard: StdGuard,
    client: StubClient,
}

impl Harness {
    fn new(seed: Vec<String>, allow_agent_passthrough: bool) -> Self {
        let mut reg = Registry::new();
        reg.add_plugin(Box::new(PassthroughPlugin::new(
            seed,
            allow_agent_passthrough,
        )));
        Self {
            reg,
            store: MemFlowStore::new(),
            guard: StdGuard::default(),
            client: StubClient,
        }
    }

    fn host(&self, frontend: Frontend) -> CommandHost<'_> {
        CommandHost::new(&self.store, &self.client, &self.guard, None).with_frontend(frontend)
    }

    fn invoke(
        &self,
        name: &str,
        args: &[(&str, Value)],
        frontend: Frontend,
    ) -> anyhow::Result<Value> {
        let params = Params::new(
            args.iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect::<BTreeMap<_, _>>(),
        );
        self.reg
            .command(name)
            .unwrap_or_else(|| panic!("{name} registered"))
            .invoke(params, &self.host(frontend))
    }
}

/// Extract the `hosts` array from a `{hosts: [...]}` result.
fn hosts_of(value: &Value) -> Vec<String> {
    let Value::Object(obj) = value else {
        panic!("result must be an object, got {value:?}");
    };
    let Some(Value::Array(items)) = obj.get("hosts") else {
        panic!("result must carry a `hosts` array, got {value:?}");
    };
    items
        .iter()
        .map(|v| match v {
            Value::Str(s) => s.clone(),
            other => panic!("host must be a string, got {other:?}"),
        })
        .collect()
}

#[test]
fn agent_add_refused_cli_allowed() {
    let h = Harness::new(vec![], false);

    // An MCP (agent) frontend is refused while the gate is off, and the refusal
    // names the config flag (mirrors scope.add).
    let err = h
        .invoke(
            "tls.passthrough.add",
            &[("host", Value::Str("pinned.example".into()))],
            Frontend::Mcp,
        )
        .expect_err("agent add must be refused when allow_agent_passthrough is false");
    assert!(
        err.to_string().contains("tls.allow_agent_passthrough"),
        "refusal should name the config flag: {err}"
    );

    // The refusal did not mutate the list.
    let listed = h
        .invoke("tls.passthrough.list", &[], Frontend::Mcp)
        .expect("list is never gated");
    assert!(
        hosts_of(&listed).is_empty(),
        "refused add must not mutate the list"
    );

    // The human CLI is always allowed; the add is reflected in the returned list.
    let added = h
        .invoke(
            "tls.passthrough.add",
            &[("host", Value::Str("pinned.example".into()))],
            Frontend::Cli,
        )
        .expect("human CLI add is always allowed");
    assert_eq!(hosts_of(&added), vec!["pinned.example"]);
}

#[test]
fn list_reflects_add_remove() {
    let h = Harness::new(vec![], false);

    let after_a = h
        .invoke(
            "tls.passthrough.add",
            &[("host", Value::Str("a.example".into()))],
            Frontend::Cli,
        )
        .expect("add a");
    assert_eq!(hosts_of(&after_a), vec!["a.example"]);

    let after_b = h
        .invoke(
            "tls.passthrough.add",
            &[("host", Value::Str("b.example".into()))],
            Frontend::Cli,
        )
        .expect("add b");
    assert_eq!(hosts_of(&after_b), vec!["a.example", "b.example"]);

    let listed = h
        .invoke("tls.passthrough.list", &[], Frontend::Cli)
        .expect("list");
    assert_eq!(hosts_of(&listed), vec!["a.example", "b.example"]);

    let after_remove = h
        .invoke(
            "tls.passthrough.remove",
            &[("host", Value::Str("a.example".into()))],
            Frontend::Cli,
        )
        .expect("remove a");
    assert_eq!(hosts_of(&after_remove), vec!["b.example"]);

    let listed = h
        .invoke("tls.passthrough.list", &[], Frontend::Cli)
        .expect("list after remove");
    assert_eq!(hosts_of(&listed), vec!["b.example"]);
}
