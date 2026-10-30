//! Stage B — the `l4.*` surface under M4's identity/policy model (L4OPS-AC4/5/6/11),
//! driven through the assembled [`L4Module`] + registry (the MCP/CLI path).
//!
//! These cover the parts enforced **inside** `aitm-proto-l4`: the per-command
//! `sensitivity()` classification (AC4), the per-capability agent gate as seen by a
//! `Frontend::Mcp` vs `Frontend::Operator` host (AC5), the operator confirm-over-the-
//! wire prompt a command offers (AC6), and the operator-only `l4.agent.*` toggle
//! (AC11 backing). The `AgentPolicy` dimension, the confirm-token lifecycle, and the
//! F2 audit log are exercised end-to-end through the MCP server in `aitm`'s own
//! integration tests.

use std::collections::BTreeMap;

use aitm_core::{
    Command, CommandHost, Frontend, HttpFlow, HttpRequest, MemFlowStore, Params, ProxyClient,
    Registry, ScopeEntry, ScopeRateGuard, Sensitivity, StdGuard, Value,
};
use aitm_proto_l4::config::{InterceptConfig, L4Config};
use aitm_proto_l4::types::{
    IpCidr, L4Capability, L4Direction, L4ScopeEntry, L4ScopeId, L4ScopeSource, PortRange, RateCap,
};
use aitm_proto_l4::{L4Module, L4Privilege};
use futures::future::BoxFuture;

// ---- scaffolding --------------------------------------------------------------

struct StubClient;
impl ProxyClient for StubClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

/// Build a registry over a module with the given config and full privilege (so the
/// commands under test are the real ones, not privilege-gated stubs).
fn registry(cfg: &L4Config) -> Registry {
    let module = L4Module::with_privilege(cfg, L4Privilege::available());
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(module));
    reg
}

/// Owns the core-host backing objects. The l4 commands read their own guard/store;
/// the core guard admits `127.0.0.1` so the defense-in-depth `check_active` passes
/// and a flag-open call reaches the L4 guard rather than the core one.
struct Parts {
    store: MemFlowStore,
    client: StubClient,
    guard: StdGuard,
}
impl Parts {
    fn new() -> Self {
        let guard = StdGuard::default();
        guard.add_scope(ScopeEntry {
            host: "127.0.0.1".into(),
        });
        Self {
            store: MemFlowStore::new(),
            client: StubClient,
            guard,
        }
    }
    fn host(&self, role: Frontend) -> CommandHost<'_> {
        CommandHost::new(&self.store, &self.client, &self.guard, None).with_frontend(role)
    }
}

/// An enabled config whose L4 scope already authorizes an inject to `127.0.0.1:9`
/// on `lo0`, so a flag-open / operator inject reaches the guard and passes it.
fn cfg_with_inject_scope() -> L4Config {
    L4Config {
        enabled: true,
        intercept: Some(InterceptConfig::default()),
        scope: vec![L4ScopeEntry {
            id: L4ScopeId::new(),
            cidr: IpCidr {
                addr: "127.0.0.1".parse().unwrap(),
                prefix: 32,
            },
            ports: PortRange { lo: 0, hi: 65535 },
            interface: "lo0".to_string(),
            direction: L4Direction::Outbound,
            capability: L4Capability::Inject,
            inject_rate: RateCap {
                pps: 100,
                burst: 100,
            },
            source: L4ScopeSource::Config,
        }],
        ..L4Config::default()
    }
}

fn udp_spec_value(dst: &str, dst_port: i64) -> Value {
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
            layer("ipv4", vec![("dst", Value::Str(dst.into()))]),
            layer("udp", vec![("dst_port", Value::Int(dst_port))]),
            raw,
        ]),
    );
    Value::Object(spec)
}

fn inject_params(dst: &str, port: i64) -> Params {
    let mut m = BTreeMap::new();
    m.insert("spec".to_string(), udp_spec_value(dst, port));
    m.insert("dst".to_string(), Value::Str(dst.into()));
    m.insert("interface".to_string(), Value::Str("lo0".into()));
    m.insert("port".to_string(), Value::Int(port));
    Params::new(m)
}

// ---- AC4: sensitivity classification ------------------------------------------

/// AC4 — every registered `l4.*` command declares the `sensitivity()` the spec §2.2
/// table requires; the wire/widen verbs are `Sensitive`, and no command silently
/// relies on a non-explicit tier.
#[test]
fn every_l4_command_is_classified_per_spec() {
    let reg = registry(&cfg_with_inject_scope());

    let expect = |name: &str| -> Sensitivity {
        match name {
            // Read
            "l4.interfaces"
            | "l4.scope.list"
            | "l4.flow.list"
            | "l4.flow.get"
            | "l4.capture.status"
            | "l4.intercept.status"
            | "l4.intercept.list"
            | "l4.craft"
            | "l4.agent.status" => Sensitivity::Read,
            // Write
            "l4.scope.remove" | "l4.capture.stop" | "l4.intercept.stop" | "l4.intercept.revert" => {
                Sensitivity::Write
            }
            // Sensitive
            "l4.scope.add"
            | "l4.capture.start"
            | "l4.inject"
            | "l4.send_recv"
            | "l4.intercept.start"
            | "l4.intercept.mutate"
            | "l4.intercept.forward"
            | "l4.intercept.drop"
            | "l4.agent.set" => Sensitivity::Sensitive,
            other => panic!("unexpected l4 command `{other}` — classify it in spec §2.2"),
        }
    };

    let mut seen = 0;
    for cmd in reg.commands().filter(|c| c.name().starts_with("l4.")) {
        assert_eq!(
            cmd.sensitivity(),
            expect(cmd.name()),
            "{} has the wrong sensitivity",
            cmd.name()
        );
        seen += 1;
    }
    assert_eq!(seen, 22, "the whole l4.* surface must be classified");
}

/// AC4 — fail-closed default: a command that declares no `sensitivity()` is
/// `Sensitive`, so an unclassified new L4 verb can never silently run autonomously.
#[test]
fn unclassified_command_defaults_sensitive() {
    struct Probe;
    impl aitm_core::Command for Probe {
        fn name(&self) -> &str {
            "l4.probe.unclassified"
        }
        fn schema(&self) -> aitm_core::ParamSchema {
            aitm_core::ParamSchema {
                description: "probe".into(),
                params: vec![],
                result: aitm_core::TypeDesc::Bool,
            }
        }
        fn invoke(&self, _a: Params, _h: &CommandHost) -> anyhow::Result<Value> {
            Ok(Value::Bool(true))
        }
    }
    assert_eq!(Probe.sensitivity(), Sensitivity::Sensitive);
}

// ---- AC5: per-capability agent gate (the flag dimension) ----------------------

/// AC5 — the per-capability flag dimension, as the command sees the caller's role.
/// Hermetic: an **out-of-scope** target is used throughout, so a call that gets past
/// the agent gate is refused by the guard (`out of L4 scope`) *before* any wire I/O —
/// which is exactly the signal that it passed the flag gate.
///
/// - flag OFF + agent → refused by the agent gate (`capability is disabled`), never
///   reaching the guard;
/// - flag ON + agent → past the gate, refused by the guard (`out of L4 scope`);
/// - operator with the flag OFF → bypasses the flag, refused by the guard.
#[test]
fn inject_agent_gate_flag_then_operator_bypass() {
    let parts = Parts::new();

    // Flag OFF (default): the agent gate refuses before the guard.
    let reg = registry(&cfg_with_inject_scope());
    let err = reg
        .command("l4.inject")
        .unwrap()
        .invoke(inject_params("8.8.8.8", 443), &parts.host(Frontend::Mcp))
        .unwrap_err();
    assert!(
        agent_gate_refused(&err),
        "flag-off agent inject must be refused by the agent gate, got: {err:#}"
    );

    // Flag ON: past the agent gate, the guard refuses the out-of-scope target.
    let cfg_on = L4Config {
        allow_agent_inject: true,
        ..cfg_with_inject_scope()
    };
    let reg_on = registry(&cfg_on);
    let err = reg_on
        .command("l4.inject")
        .unwrap()
        .invoke(inject_params("8.8.8.8", 443), &parts.host(Frontend::Mcp))
        .unwrap_err();
    assert!(
        guard_refused(&err),
        "flag-on agent inject must pass the agent gate and be refused by the guard, got: {err:#}"
    );

    // Operator bypasses the flag (off here): it too reaches the guard.
    let err = reg
        .command("l4.inject")
        .unwrap()
        .invoke(
            inject_params("8.8.8.8", 443),
            &parts.host(Frontend::Operator),
        )
        .unwrap_err();
    assert!(
        guard_refused(&err),
        "operator inject must bypass the flag and reach the guard, got: {err:#}"
    );
}

/// Whether an invoke error is the agent gate's refusal (flag off).
fn agent_gate_refused(err: &anyhow::Error) -> bool {
    format!("{err:#}").contains("capability is disabled")
}

/// Whether an invoke error is the L4 guard's refusal (reached the guard).
fn guard_refused(err: &anyhow::Error) -> bool {
    format!("{err:#}").contains("out of L4 scope")
}

// ---- AC6: operator confirm-over-the-wire prompt -------------------------------

/// AC6 — `l4.inject`'s `confirm_prompt` offers a wire summary for an in-scope target
/// (so the server mints a token and asks), and offers **nothing** for an out-of-scope
/// target (so no token is minted; the guard refuses in `invoke` instead).
#[test]
fn inject_confirm_prompt_in_scope_some_out_of_scope_none() {
    let reg = registry(&cfg_with_inject_scope());
    let inject = reg.command("l4.inject").unwrap();

    let prompt = inject
        .confirm_prompt(&inject_params("127.0.0.1", 9))
        .expect("an in-scope inject offers a confirm summary");
    assert!(
        prompt.contains("127.0.0.1") && prompt.contains("l4.inject") && prompt.contains("_confirm"),
        "the summary must name the destination and ask to confirm, got: {prompt}"
    );

    assert!(
        inject
            .confirm_prompt(&inject_params("8.8.8.8", 443))
            .is_none(),
        "an out-of-scope inject must offer no confirmation (so no token is minted)"
    );
}

// ---- AC11: operator-only l4.agent.set / l4.agent.status -----------------------

/// AC11 backing — the operator toggles a gate and `l4.agent.status` reflects it; an
/// agent (`Frontend::Mcp`) call to `l4.agent.set` is refused outright, and cannot
/// read-then-flip its own gates.
#[test]
fn agent_toggle_is_operator_only_and_governs_the_gate() {
    let reg = registry(&cfg_with_inject_scope());
    let parts = Parts::new();

    // Default: every gate is off.
    let status = reg
        .command("l4.agent.status")
        .unwrap()
        .invoke(Params::default(), &parts.host(Frontend::Operator))
        .expect("status ok");
    assert_eq!(gate(&status, "inject"), Some(false));

    // An agent cannot flip its own gate.
    let mut set_args = BTreeMap::new();
    set_args.insert("capability".to_string(), Value::Str("inject".into()));
    set_args.insert("allowed".to_string(), Value::Bool(true));
    let agent_set = reg
        .command("l4.agent.set")
        .unwrap()
        .invoke(Params::new(set_args.clone()), &parts.host(Frontend::Mcp))
        .unwrap_err();
    assert!(
        format!("{agent_set:#}").contains("the agent cannot change its own L4 gates"),
        "an agent l4.agent.set must be refused"
    );

    // The operator flips it; status reflects the change.
    reg.command("l4.agent.set")
        .unwrap()
        .invoke(Params::new(set_args), &parts.host(Frontend::Operator))
        .expect("operator set ok");
    let status = reg
        .command("l4.agent.status")
        .unwrap()
        .invoke(Params::default(), &parts.host(Frontend::Operator))
        .expect("status ok");
    assert_eq!(
        gate(&status, "inject"),
        Some(true),
        "the operator's toggle must be reflected in status"
    );

    // And it governs the real agent path: a Mcp inject now passes the agent gate and
    // is refused only by the guard (out-of-scope target → no wire I/O).
    let err = reg
        .command("l4.inject")
        .unwrap()
        .invoke(inject_params("8.8.8.8", 443), &parts.host(Frontend::Mcp))
        .unwrap_err();
    assert!(
        guard_refused(&err),
        "after the operator opened the gate, the agent inject must reach the guard, got: {err:#}"
    );
}

fn gate(status: &Value, cap: &str) -> Option<bool> {
    match status {
        Value::Object(o) => match o.get(cap) {
            Some(Value::Bool(b)) => Some(*b),
            _ => None,
        },
        _ => None,
    }
}
