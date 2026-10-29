//! M5 exit gate — the `l4.*` command surface, assembled and driven end-to-end
//! through the public module + registry (M5 plan Task 15).
//!
//! Unlike the per-command unit tests (which construct each `Command` directly), these
//! drive the **fully assembled** [`L4Module`] after it is loaded into a core
//! [`Registry`] — the exact path MCP `tools/list` / `tools/call` and the CLI take —
//! so they prove the module's own wiring, not just a single command in isolation.
//!
//! - **AC18 — reachable everywhere:** every `l4.*` command appears in the registry
//!   (the one bus MCP and the CLI read), so each is invocable over both.
//! - **AC17 / AC16 — fail-closed, honest surface:** with the module opted in but no
//!   privilege, the full surface is still registered (drivable), every wire-touching
//!   verb fails closed with a typed `L4Unavailable` naming the missing capability, and
//!   every pure/read verb still works.
//!
//! The Rhai tier is deliberately **out of scope** for M5 (deferred to the
//! protocol-extensibility seam), so AC18's Rhai clause is not exercised here.

use std::collections::BTreeMap;

use aitm_core::{
    CommandHost, HttpFlow, HttpRequest, MemFlowStore, Params, ProxyClient, Registry, StdGuard,
    Value,
};
use aitm_proto_l4::config::{InterceptConfig, L4Config};
use aitm_proto_l4::{L4Error, L4Module, L4Privilege};
use futures::future::BoxFuture;

/// The complete `l4.*` surface the module registers. If a command is added or renamed,
/// this list (and the operator-facing `tools/list`) must change with it.
const L4_COMMANDS: &[&str] = &[
    // read-only / pure
    "l4.interfaces",
    "l4.craft",
    "l4.flow.list",
    "l4.flow.get",
    // scope management
    "l4.scope.add",
    "l4.scope.remove",
    "l4.scope.list",
    // wire-touching (capture/inject/send-recv)
    "l4.capture.start",
    "l4.capture.stop",
    "l4.capture.status",
    "l4.inject",
    "l4.send_recv",
    // in-path interception
    "l4.intercept.start",
    "l4.intercept.stop",
    "l4.intercept.status",
    "l4.intercept.list",
    "l4.intercept.mutate",
    "l4.intercept.revert",
    "l4.intercept.forward",
    "l4.intercept.drop",
];

/// The l4 commands never reissue HTTP; the core host still requires a client.
struct StubClient;
impl ProxyClient for StubClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

/// An enabled config with in-path interception configured (so `l4.intercept.*` is a
/// live part of the surface, not disabled).
fn enabled_cfg() -> L4Config {
    L4Config {
        enabled: true,
        intercept: Some(InterceptConfig::default()),
        // These exit-gate tests drive the real `l4.scope.add` round-trip, so they
        // opt into runtime scope widening (the gate itself is covered in `module.rs`).
        allow_agent_widen: true,
        ..L4Config::default()
    }
}

/// Assemble `module` into a fresh registry, exactly as the binary does.
fn registry_for(module: L4Module) -> Registry {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(module));
    reg
}

fn one(key: &str, value: Value) -> Params {
    let mut m = BTreeMap::new();
    m.insert(key.to_string(), value);
    Params::new(m)
}

/// An IPv4/UDP/Raw craft spec in the `Value` shape `l4.craft` / `l4.inject` accept.
fn craft_spec() -> Value {
    let layer = |k: &str, fields: Vec<(&str, Value)>| {
        let inner: BTreeMap<String, Value> = fields
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        let mut l = BTreeMap::new();
        l.insert(k.to_string(), Value::Object(inner));
        Value::Object(l)
    };
    let raw = {
        let mut l = BTreeMap::new();
        l.insert(
            "raw".to_string(),
            Value::Array(b"probe".iter().map(|b| Value::Int(i64::from(*b))).collect()),
        );
        Value::Object(l)
    };
    let mut spec = BTreeMap::new();
    spec.insert(
        "layers".to_string(),
        Value::Array(vec![
            layer("ipv4", vec![("dst", Value::Str("127.0.0.1".into()))]),
            layer("udp", vec![("dst_port", Value::Int(9))]),
            raw,
        ]),
    );
    Value::Object(spec)
}

fn scope_add_params() -> Params {
    let mut m = BTreeMap::new();
    m.insert("cidr".to_string(), Value::Str("127.0.0.1/32".into()));
    m.insert("interface".to_string(), Value::Str("lo0".into()));
    m.insert("direction".to_string(), Value::Str("outbound".into()));
    m.insert("capability".to_string(), Value::Str("inject".into()));
    m.insert("ports".to_string(), Value::Str("1-1024".into()));
    m.insert("inject_rate_pps".to_string(), Value::Int(5));
    Params::new(m)
}

/// AC18 — every `l4.*` command is registered on the bus when the module is enabled,
/// so MCP `tools/list` and the CLI can reach the whole surface.
#[test]
fn full_l4_surface_is_registered() {
    let module = L4Module::with_privilege(&enabled_cfg(), L4Privilege::available());
    let reg = registry_for(module);

    for name in L4_COMMANDS {
        assert!(
            reg.command(name).is_some(),
            "{name} must be registered so it reaches MCP/CLI (AC18)"
        );
    }

    // And the registry advertises exactly the l4 surface we expect — no stray or
    // missing verbs.
    let registered: Vec<&str> = reg
        .commands()
        .map(|c| c.name())
        .filter(|n| n.starts_with("l4."))
        .collect();
    assert_eq!(
        registered.len(),
        L4_COMMANDS.len(),
        "the registered l4.* surface {registered:?} must match the expected {L4_COMMANDS:?}"
    );
}

/// AC17 / AC16 — opted in but unprivileged: the full surface stays registered (honest,
/// drivable), every wire-touching verb fails closed with a typed `L4Unavailable`
/// naming the missing capability, and every pure/read verb still works. Hermetic:
/// forces a known no-privilege state, so it runs on any host.
#[test]
fn unprivileged_wire_verbs_unavailable_pure_verbs_work() {
    let unprivileged = L4Privilege {
        capture_inject: Some("missing CAP_NET_RAW / /dev/bpf access".into()),
        intercept: Some("missing CAP_NET_ADMIN".into()),
    };
    let module = L4Module::with_privilege(&enabled_cfg(), unprivileged);
    let reg = registry_for(module);

    let store = MemFlowStore::new();
    let client = StubClient;
    let guard = StdGuard::default();
    let host = CommandHost::new(&store, &client, &guard, None);

    // Every wire-touching verb fails closed with a typed L4Unavailable.
    let wire_verbs = [
        ("l4.inject", one("spec", craft_spec())),
        (
            "l4.capture.start",
            one("interface", Value::Str("lo0".into())),
        ),
        ("l4.send_recv", one("spec", craft_spec())),
        (
            "l4.intercept.start",
            one("interface", Value::Str("lo0".into())),
        ),
    ];
    for (name, params) in wire_verbs {
        let err = reg
            .command(name)
            .unwrap_or_else(|| panic!("{name} registered"))
            .invoke(params, &host)
            .expect_err(&format!("{name} must fail closed without privilege"));
        let l4 = err
            .downcast_ref::<L4Error>()
            .unwrap_or_else(|| panic!("{name}: want a typed L4Error, got {err:?}"));
        assert!(
            matches!(l4, L4Error::Unavailable(_)),
            "{name} must return L4Unavailable without privilege, got {l4:?}"
        );
    }

    // Every pure / read / scope verb still works without privilege.
    reg.command("l4.interfaces")
        .unwrap()
        .invoke(Params::default(), &host)
        .expect("l4.interfaces works unprivileged");
    reg.command("l4.craft")
        .unwrap()
        .invoke(one("spec", craft_spec()), &host)
        .expect("l4.craft works unprivileged");
    reg.command("l4.flow.list")
        .unwrap()
        .invoke(Params::default(), &host)
        .expect("l4.flow.list works unprivileged");
    let added = reg
        .command("l4.scope.add")
        .unwrap()
        .invoke(scope_add_params(), &host)
        .expect("l4.scope.add works unprivileged");
    assert!(matches!(added, Value::Str(_)), "scope.add returns an id");
    reg.command("l4.scope.list")
        .unwrap()
        .invoke(Params::default(), &host)
        .expect("l4.scope.list works unprivileged");
}
