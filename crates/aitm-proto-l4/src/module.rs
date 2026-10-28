//! The L4 plugin module (M5 Task 9).
//!
//! `aitm-proto-l4` is **command-driven**, not acceptor-driven: it has no listening
//! socket to take over, so it rides the core [`Plugin`] + [`Command`] seams rather
//! than the `ProtocolModule` acceptor seam. [`L4Module`] is the one [`Plugin`]; its
//! [`load`](L4Module::load) registers every `l4.*` command into the [`Registry`],
//! so MCP, the CLI, and the Rhai tier reach them through the single command bus.
//!
//! The module owns the two pieces of L4 state the core [`CommandHost`] does not
//! carry — the deny-by-default [`L4Guard`] and the l4-owned [`L4FlowStore`] — and
//! hands each command an `Arc` to them. (The core [`CommandHost`] stays
//! HTTP-shaped; L4 state living here is how M5 lands with zero `aitm-core` edits.)
//! The binary (M5 Task 13) constructs the module only when `enabled` and privilege
//! are present.
//!
//! This task registers the **no-wire** commands only. The wire commands
//! (`l4.capture.*`, `l4.inject`, `l4.send_recv`, `l4.intercept.*`) are added in
//! M5 Tasks 10 and 12, where they compose [`L4Guard::check`] with the core
//! [`ScopeRateGuard::check_active`] at this same layer.
//!
//! [`Plugin`]: aitm_core::Plugin
//! [`Command`]: aitm_core::Command
//! [`Registry`]: aitm_core::Registry
//! [`CommandHost`]: aitm_core::CommandHost
//! [`L4Guard`]: crate::guard::L4Guard
//! [`L4FlowStore`]: crate::flow::L4FlowStore
//! [`L4Guard::check`]: crate::guard::L4Guard::check
//! [`ScopeRateGuard::check_active`]: aitm_core::ScopeRateGuard::check_active

use std::sync::Arc;

use aitm_core::{Plugin, Registry};

use crate::config::L4Config;
use crate::flow::{InMemoryL4FlowStore, L4FlowStore};
use crate::guard::L4Guard;

/// The L4 protocol feature as a core [`Plugin`]. Holds the shared guard + flow
/// store and registers the `l4.*` command surface.
pub struct L4Module {
    guard: Arc<L4Guard>,
    store: Arc<dyn L4FlowStore>,
}

impl L4Module {
    /// Build a module from config: a guard seeded from `cfg.scope` and a fresh
    /// bounded in-memory flow store. The binary (M5 Task 13) is the only caller in
    /// production; tests construct it directly.
    #[must_use]
    pub fn new(cfg: &L4Config) -> Self {
        Self {
            guard: Arc::new(L4Guard::new(cfg)),
            store: Arc::new(InMemoryL4FlowStore::new()),
        }
    }

    /// Build a module over an already-shared guard + store (for wiring that owns
    /// the guard elsewhere, and for tests).
    #[must_use]
    pub fn with_parts(guard: Arc<L4Guard>, store: Arc<dyn L4FlowStore>) -> Self {
        Self { guard, store }
    }

    /// The shared deny-by-default guard (an `Arc` clone).
    #[must_use]
    pub fn guard(&self) -> Arc<L4Guard> {
        self.guard.clone()
    }

    /// The shared l4-owned flow store (an `Arc` clone).
    #[must_use]
    pub fn store(&self) -> Arc<dyn L4FlowStore> {
        self.store.clone()
    }
}

impl Plugin for L4Module {
    fn name(&self) -> &str {
        "l4"
    }

    fn load(&mut self, reg: &mut Registry) {
        for cmd in crate::commands::active_commands(self.guard(), self.store()) {
            reg.add_command(cmd);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use aitm_core::{
        CommandHost, HttpFlow, HttpRequest, MemFlowStore, Params, ProxyClient, Registry, StdGuard,
        Value,
    };
    use futures::future::BoxFuture;

    use super::*;

    /// The l4 commands never reissue HTTP; the core host still requires a client.
    struct StubClient;
    impl ProxyClient for StubClient {
        fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            Box::pin(async { anyhow::bail!("stub client") })
        }
    }

    /// A core `CommandHost` the l4 commands can be invoked against. The l4 commands
    /// read their own guard/store (the module's), so the host's store/guard are
    /// only there to satisfy the signature.
    fn host<'a>(
        store: &'a MemFlowStore,
        client: &'a StubClient,
        guard: &'a StdGuard,
    ) -> CommandHost<'a> {
        CommandHost::new(store, client, guard, None)
    }

    fn registered(cfg: &L4Config) -> (Registry, Arc<L4Guard>, Arc<dyn L4FlowStore>) {
        let module = L4Module::new(cfg);
        let guard = module.guard();
        let store = module.store();
        let mut reg = Registry::new();
        reg.add_plugin(Box::new(module));
        (reg, guard, store)
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

    /// An IPv4/UDP/Raw craft spec in the `Value` shape `l4.craft` accepts
    /// (`Layer` is externally tagged with snake_case variant names).
    fn craft_spec() -> Value {
        let ipv4 = {
            let mut m = BTreeMap::new();
            m.insert("dst".to_string(), Value::Str("127.0.0.1".into()));
            let mut l = BTreeMap::new();
            l.insert("ipv4".to_string(), Value::Object(m));
            Value::Object(l)
        };
        let udp = {
            let mut m = BTreeMap::new();
            m.insert("dst_port".to_string(), Value::Int(9));
            let mut l = BTreeMap::new();
            l.insert("udp".to_string(), Value::Object(m));
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
        spec.insert("layers".to_string(), Value::Array(vec![ipv4, udp, raw]));
        Value::Object(spec)
    }

    fn craft_params() -> Params {
        let mut m = BTreeMap::new();
        m.insert("spec".to_string(), craft_spec());
        Params::new(m)
    }

    /// Pinned (plan Task 9): `load` registers the command surface; `l4.craft` and
    /// `l4.scope.add` are present; invoking `l4.craft` with an IPv4/UDP/`"probe"`
    /// spec returns the built length (33 = 20 IPv4 + 8 UDP + 5 payload) + a summary.
    #[test]
    fn commands_registered() {
        let (reg, _g, _s) = registered(&L4Config::default());

        for name in [
            "l4.interfaces",
            "l4.scope.add",
            "l4.scope.remove",
            "l4.scope.list",
            "l4.flow.list",
            "l4.flow.get",
            "l4.craft",
        ] {
            assert!(reg.command(name).is_some(), "{name} must be registered");
        }

        let store = MemFlowStore::new();
        let client = StubClient;
        let guard = StdGuard::default();
        let h = host(&store, &client, &guard);

        let result = reg
            .command("l4.craft")
            .expect("l4.craft registered")
            .invoke(craft_params(), &h)
            .expect("l4.craft ok");
        let Value::Object(obj) = result else {
            panic!("l4.craft must return an object");
        };
        assert_eq!(obj.get("length"), Some(&Value::Int(33)));
        let Some(Value::Bytes(bytes)) = obj.get("bytes") else {
            panic!("l4.craft must return bytes");
        };
        assert_eq!(bytes.len(), 33);
        let Some(Value::Object(summary)) = obj.get("summary") else {
            panic!("l4.craft must return a summary");
        };
        assert_eq!(
            summary.get("layers"),
            Some(&Value::Array(vec![
                Value::Str("IPv4".into()),
                Value::Str("UDP".into()),
            ]))
        );
        assert_eq!(summary.get("length"), Some(&Value::Int(33)));
    }

    /// Pinned (plan Task 9): `l4.scope.add` then `l4.scope.list` round-trips an
    /// entry — the listed entry carries exactly the fields that were added, and the
    /// add result is its id.
    #[test]
    fn scope_add_then_list() {
        let (reg, guard, _s) = registered(&L4Config::default());
        let store = MemFlowStore::new();
        let client = StubClient;
        let core_guard = StdGuard::default();
        let h = host(&store, &client, &core_guard);

        // Deny-by-default: empty to start.
        assert!(guard.list_scope().is_empty());

        let added = reg
            .command("l4.scope.add")
            .expect("l4.scope.add registered")
            .invoke(scope_add_params(), &h)
            .expect("l4.scope.add ok");
        let Value::Str(id) = added else {
            panic!("l4.scope.add must return the entry id");
        };
        assert!(!id.is_empty());

        // The guard now holds exactly that entry.
        let scope = guard.list_scope();
        assert_eq!(scope.len(), 1);

        let listed = reg
            .command("l4.scope.list")
            .expect("l4.scope.list registered")
            .invoke(Params::default(), &h)
            .expect("l4.scope.list ok");
        let Value::Array(entries) = listed else {
            panic!("l4.scope.list must return an array");
        };
        assert_eq!(entries.len(), 1);
        let Value::Object(entry) = &entries[0] else {
            panic!("a scope entry must be an object");
        };
        assert_eq!(entry.get("id"), Some(&Value::Str(id)));
        assert_eq!(entry.get("cidr"), Some(&Value::Str("127.0.0.1/32".into())));
        assert_eq!(entry.get("ports"), Some(&Value::Str("1-1024".into())));
        assert_eq!(entry.get("interface"), Some(&Value::Str("lo0".into())));
        assert_eq!(entry.get("direction"), Some(&Value::Str("outbound".into())));
        assert_eq!(entry.get("capability"), Some(&Value::Str("inject".into())));
        let Some(Value::Object(rate)) = entry.get("inject_rate") else {
            panic!("a scope entry must carry inject_rate");
        };
        assert_eq!(rate.get("pps"), Some(&Value::Int(5)));
        assert_eq!(rate.get("burst"), Some(&Value::Int(5)));
    }

    /// `l4.scope.remove` by id reverts to deny-by-default; an unknown id ⇒ `false`.
    #[test]
    fn scope_remove_by_id() {
        let (reg, guard, _s) = registered(&L4Config::default());
        let store = MemFlowStore::new();
        let client = StubClient;
        let core_guard = StdGuard::default();
        let h = host(&store, &client, &core_guard);

        let Value::Str(id) = reg
            .command("l4.scope.add")
            .unwrap()
            .invoke(scope_add_params(), &h)
            .unwrap()
        else {
            panic!("id");
        };
        assert_eq!(guard.list_scope().len(), 1);

        let mut m = BTreeMap::new();
        m.insert("id".to_string(), Value::Str(id));
        let removed = reg
            .command("l4.scope.remove")
            .unwrap()
            .invoke(Params::new(m), &h)
            .expect("remove ok");
        assert_eq!(removed, Value::Bool(true));
        assert!(guard.list_scope().is_empty());

        // A second remove of the same id (now gone) is `false`, not an error.
        let mut m = BTreeMap::new();
        m.insert(
            "id".to_string(),
            Value::Str(crate::commands::scope_id_to_string(
                crate::types::L4ScopeId::new(),
            )),
        );
        let removed = reg
            .command("l4.scope.remove")
            .unwrap()
            .invoke(Params::new(m), &h)
            .expect("remove ok");
        assert_eq!(removed, Value::Bool(false));
    }

    /// `l4.flow.get` round-trips a flow inserted into the module's own store:
    /// `l4.flow.list` shows its id and `l4.flow.get` summarizes it, including the
    /// injected packet. Proves the commands read the l4-owned store (no core edit).
    #[test]
    fn flow_list_and_get() {
        use crate::craft::PacketSummary;
        use crate::flow::{L4Bind, L4Flow, L4FlowId, L4FlowKind, L4Meta, L4Packet};
        use crate::types::L4Direction;

        let (reg, _g, store) = registered(&L4Config::default());
        let mem = MemFlowStore::new();
        let client = StubClient;
        let core_guard = StdGuard::default();
        let h = host(&mem, &client, &core_guard);

        let id = store.insert(L4Flow {
            id: L4FlowId::new(),
            kind: L4FlowKind::Craft,
            bind: L4Bind {
                interface: "lo0".into(),
                filter: None,
                queue: None,
            },
            packets: vec![L4Packet {
                dir: L4Direction::Outbound,
                timestamp: std::time::SystemTime::now(),
                bytes: vec![0u8; 33],
                decoded: PacketSummary {
                    layers: vec!["IPv4".into(), "UDP".into()],
                    length: 33,
                },
                injected: true,
            }],
            metadata: L4Meta::default(),
        });

        let listed = reg
            .command("l4.flow.list")
            .unwrap()
            .invoke(Params::default(), &h)
            .expect("flow.list ok");
        let id_str = crate::commands::flow_id_to_string(id);
        assert_eq!(listed, Value::Array(vec![Value::Str(id_str.clone())]));

        let mut m = BTreeMap::new();
        m.insert("id".to_string(), Value::Str(id_str.clone()));
        let got = reg
            .command("l4.flow.get")
            .unwrap()
            .invoke(Params::new(m), &h)
            .expect("flow.get ok");
        let Value::Object(obj) = got else {
            panic!("flow.get returns an object");
        };
        assert_eq!(obj.get("id"), Some(&Value::Str(id_str)));
        assert_eq!(obj.get("kind"), Some(&Value::Str("craft".into())));
        assert_eq!(obj.get("interface"), Some(&Value::Str("lo0".into())));
        assert_eq!(obj.get("packet_count"), Some(&Value::Int(1)));
        assert_eq!(obj.get("injected_count"), Some(&Value::Int(1)));
    }
}
