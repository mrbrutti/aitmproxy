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

use aitm_core::{Command, CommandHost, ParamSchema, Params, Plugin, Registry, Value};

use crate::backend::L4Error;
use crate::commands::intercept::InterceptSessions;
use crate::config::{InterceptConfig, L4Config};
use crate::flow::{InMemoryL4FlowStore, L4FlowStore};
use crate::guard::L4Guard;

/// The result of the cheap startup capability probe, cached into [`L4Module`] so
/// each wire-touching command returns the specific missing-capability reason without
/// re-probing. `Some(reason)` means that class of capability is **unavailable**.
///
/// The two classes mirror the spec's privilege model:
/// - `capture_inject` — raw capture/inject (`l4.capture.*`, `l4.inject`,
///   `l4.send_recv`): Linux `CAP_NET_RAW`, macOS `/dev/bpf*` read+write.
/// - `intercept` — in-path NFQUEUE (`l4.intercept.*`): Linux `CAP_NET_ADMIN`;
///   unsupported on macOS and other platforms.
#[derive(Debug, Clone)]
pub struct L4Privilege {
    /// `Some(reason)` ⇒ raw capture/inject is unavailable (names the missing cap).
    pub capture_inject: Option<String>,
    /// `Some(reason)` ⇒ in-path interception is unavailable (names the missing cap).
    pub intercept: Option<String>,
}

impl L4Privilege {
    /// Both capability classes present (for wiring/tests that know they are).
    #[must_use]
    pub fn available() -> Self {
        Self {
            capture_inject: None,
            intercept: None,
        }
    }

    /// Both classes unavailable for one reason (unsupported platform / no process
    /// capability info). Only the Linux and fallback probes use it; macOS always
    /// splits capture/inject from the (unsupported) in-path class.
    #[cfg(not(target_os = "macos"))]
    fn unavailable_both(reason: &str) -> Self {
        Self {
            capture_inject: Some(reason.to_string()),
            intercept: Some(reason.to_string()),
        }
    }

    /// Run the cheap startup capability probe for this platform. Never opens a raw
    /// socket against a target; fails **closed** (reports unavailable) on any doubt.
    #[must_use]
    pub fn probe() -> Self {
        probe()
    }
}

/// Linux: read the effective capability set from `/proc/self/status` and check the
/// `CAP_NET_RAW` / `CAP_NET_ADMIN` bits. Unreadable / unparsable ⇒ fail-closed.
#[cfg(target_os = "linux")]
fn probe() -> L4Privilege {
    const CAP_NET_ADMIN: u32 = 12;
    const CAP_NET_RAW: u32 = 13;

    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(e) => {
            return L4Privilege::unavailable_both(&format!(
                "could not read process capabilities (/proc/self/status: {e})"
            ))
        }
    };
    let Some(bits) = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
    else {
        return L4Privilege::unavailable_both(
            "could not read effective capabilities from /proc/self/status",
        );
    };
    let has = |cap: u32| bits & (1u64 << cap) != 0;
    L4Privilege {
        capture_inject: (!has(CAP_NET_RAW)).then(|| {
            "missing CAP_NET_RAW (raw capture/inject needs `setcap cap_net_raw+ep` on the \
             binary, or root)"
                .to_string()
        }),
        intercept: (!has(CAP_NET_ADMIN)).then(|| {
            "missing CAP_NET_ADMIN (in-path NFQUEUE needs `setcap cap_net_admin+ep` on the \
             binary, or root)"
                .to_string()
        }),
    }
}

/// macOS: capture/inject goes through `/dev/bpf*` (read=capture, write=inject), so
/// the first device node that opens read+write proves the capability. In-path
/// interception is unsupported (no NFQUEUE), matching the fail-closed spec.
#[cfg(target_os = "macos")]
fn probe() -> L4Privilege {
    use std::io::ErrorKind;

    let mut capture_inject = Some(
        "no read+write access to any /dev/bpf* device (capture/inject needs it; install \
         ChmodBPF or run with privilege)"
            .to_string(),
    );
    for n in 0..256u32 {
        let path = format!("/dev/bpf{n}");
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
        {
            // Opened read+write ⇒ capture+inject available; the handle drops at once.
            Ok(_f) => {
                capture_inject = None;
                break;
            }
            Err(e) => match e.kind() {
                ErrorKind::NotFound => break, // past the last device node
                _ => continue,                // denied / busy: try the next node
            },
        }
    }
    L4Privilege {
        capture_inject,
        intercept: Some(
            "in-path interception is unsupported on macOS (Linux CAP_NET_ADMIN / NFQUEUE only)"
                .to_string(),
        ),
    }
}

/// Other platforms have no supported capture/inject or in-path backend: fail-closed.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn probe() -> L4Privilege {
    L4Privilege::unavailable_both("no supported L4 capture/inject backend on this platform")
}

/// A wire-touching `l4.*` command wrapped so that, when the startup probe found the
/// required capability absent, every invocation returns a typed
/// [`L4Error::Unavailable`] naming the missing capability — without touching the wire
/// or re-probing. `name`/`schema` delegate to the inner command, so the command still
/// appears, honestly, in `tools/list`.
struct L4Gated {
    inner: Arc<dyn Command>,
    reason: String,
}

impl Command for L4Gated {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn schema(&self) -> ParamSchema {
        self.inner.schema()
    }

    fn sensitivity(&self) -> aitm_core::Sensitivity {
        // Classify honestly even while unavailable, so `tools/list` and the policy
        // gate see the real tier (all gated verbs are Sensitive, but delegate rather
        // than assume).
        self.inner.sensitivity()
    }

    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        Err(anyhow::Error::new(L4Error::Unavailable(
            self.reason.clone(),
        )))
    }
}

/// Wrap each command in `cmds` as [`L4Gated`] when `reason` is `Some` (the capability
/// is unavailable); otherwise leave them live.
fn gate(cmds: Vec<Arc<dyn Command>>, reason: Option<&str>) -> Vec<Arc<dyn Command>> {
    match reason {
        None => cmds,
        Some(reason) => cmds
            .into_iter()
            .map(|inner| {
                Arc::new(L4Gated {
                    inner,
                    reason: reason.to_string(),
                }) as Arc<dyn Command>
            })
            .collect(),
    }
}

/// The L4 protocol feature as a core [`Plugin`]. Holds the shared guard + flow
/// store and registers the `l4.*` command surface.
pub struct L4Module {
    guard: Arc<L4Guard>,
    store: Arc<dyn L4FlowStore>,
    /// In-path interception config; `None` ⇒ `l4.intercept.*` is `L4Unavailable`.
    intercept_cfg: Option<InterceptConfig>,
    /// Live `l4.intercept` sessions, shared with the intercept commands so a
    /// session started by one call outlives it.
    sessions: Arc<InterceptSessions>,
    /// The cached startup capability probe: wire verbs are gated on it, fail-closed.
    privilege: L4Privilege,
}

impl L4Module {
    /// Build a module from config, running the cheap startup capability probe. The
    /// binary (M5 Task 13) is the only caller in production; tests that want a known
    /// privilege state use [`with_privilege`](L4Module::with_privilege).
    #[must_use]
    pub fn new(cfg: &L4Config) -> Self {
        Self::with_privilege(cfg, L4Privilege::probe())
    }

    /// Build a module from config over an explicit capability probe result. The
    /// binary passes the real probe (or a configured override); tests force a known
    /// privilege state. Wire-touching verbs are gated on `privilege`, fail-closed.
    #[must_use]
    pub fn with_privilege(cfg: &L4Config, privilege: L4Privilege) -> Self {
        Self {
            guard: Arc::new(L4Guard::new(cfg)),
            store: Arc::new(InMemoryL4FlowStore::new()),
            intercept_cfg: cfg.intercept.clone(),
            sessions: Arc::new(InterceptSessions::new()),
            privilege,
        }
    }

    /// Build a module over an already-shared guard + store (for wiring that owns
    /// the guard elsewhere, and for tests). `intercept_cfg` carries the in-path
    /// settings; `None` disables `l4.intercept.*`. Assumes privilege is present
    /// (the caller owns the guard and the capability decision).
    #[must_use]
    pub fn with_parts(
        guard: Arc<L4Guard>,
        store: Arc<dyn L4FlowStore>,
        intercept_cfg: Option<InterceptConfig>,
    ) -> Self {
        Self {
            guard,
            store,
            intercept_cfg,
            sessions: Arc::new(InterceptSessions::new()),
            privilege: L4Privilege::available(),
        }
    }

    /// Build a module over an **already-shared** guard + store, keeping the
    /// fail-closed privilege gate. Unlike [`with_parts`](L4Module::with_parts)
    /// (which assumes privilege present), this takes the real startup probe so the
    /// wire verbs still fail closed when a capability is absent — the production
    /// path when the binary owns the guard/store so the scripting engine's
    /// [`L4Language`](crate::language::L4Language) and this command module act over
    /// the **same** L4 engagement state (no divergent guard/store).
    #[must_use]
    pub fn with_shared(
        guard: Arc<L4Guard>,
        store: Arc<dyn L4FlowStore>,
        intercept_cfg: Option<InterceptConfig>,
        privilege: L4Privilege,
    ) -> Self {
        Self {
            guard,
            store,
            intercept_cfg,
            sessions: Arc::new(InterceptSessions::new()),
            privilege,
        }
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
        // The single shared agent-gate object the guard owns: the Mcp-only wrapper and
        // the `l4.agent.*` commands read/flip the same gates the guard's
        // `add_runtime_scope` enforces, so an operator toggle is one live source of truth.
        let gates = self.guard.agent_gates();
        // The pure/read verbs (`l4.interfaces`, `l4.scope.*`, `l4.flow.*`, `l4.craft`)
        // work regardless of privilege — never privilege-gated. `l4.scope.add`'s widen
        // gate lives in the guard (`add_runtime_scope`), so these are unwrapped.
        for cmd in crate::commands::active_commands(self.guard(), self.store()) {
            reg.add_command(cmd);
        }
        // M5 Task 10 — the wire-touching commands (`l4.capture.*`, `l4.inject`,
        // `l4.send_recv`). Two layers wrap each Sensitive verb: the Mcp-only
        // per-capability agent gate (`agent_gate`, inner), then the fail-closed
        // privilege gate (`gate`, outer) so an unprivileged core returns a typed
        // `L4Unavailable` before the flag is even consulted. The operator who opted in
        // still sees an honest, drivable surface (amended M5 Task 13).
        for cmd in gate(
            crate::commands::agent_gate(
                crate::commands::wire_commands(self.guard(), self.store()),
                &gates,
            ),
            self.privilege.capture_inject.as_deref(),
        ) {
            reg.add_command(cmd);
        }
        // The in-path interception commands (M5 Task 12) register additively over
        // the shared session registry, so a `start` outlives the call and the later
        // verdict commands reach it. Agent-gated (`intercept` capability) then
        // privilege-gated on in-path (`CAP_NET_ADMIN`) the same way.
        for cmd in gate(
            crate::commands::agent_gate(
                crate::commands::intercept::intercept_commands(
                    self.guard(),
                    self.store(),
                    self.sessions.clone(),
                    self.intercept_cfg.clone(),
                ),
                &gates,
            ),
            self.privilege.intercept.as_deref(),
        ) {
            reg.add_command(cmd);
        }
        // The operator-only live toggle: `l4.agent.status` (read the four gates) and
        // `l4.agent.set` (flip one). Never privilege- or agent-gated here — the set
        // command self-gates to operator/CLI, and status is read-only.
        for cmd in crate::commands::agent_commands(gates.clone()) {
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
        // Known privilege state: these tests exercise the command surface, not the
        // real platform probe (which they must not depend on).
        let module = L4Module::with_privilege(cfg, L4Privilege::available());
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
        // This test exercises the runtime add→list round-trip, so it opts into
        // scope widening; the gate itself is covered by
        // `scope_add_refused_when_widen_disabled`.
        let cfg = L4Config {
            allow_agent_widen: true,
            ..L4Config::default()
        };
        let (reg, guard, _s) = registered(&cfg);
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
        // Needs a runtime add to then remove ⇒ opt into widening.
        let cfg = L4Config {
            allow_agent_widen: true,
            ..L4Config::default()
        };
        let (reg, guard, _s) = registered(&cfg);
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

    /// A single operator-declared scope entry (on `eth0`, `10.0.0.0/8`), carrying
    /// `source: Config`, so tests can prove it survives a refused runtime add.
    fn config_declared_entry() -> crate::types::L4ScopeEntry {
        use crate::types::{IpCidr, L4ScopeEntry, L4ScopeId, L4ScopeSource, PortRange, RateCap};
        L4ScopeEntry {
            id: L4ScopeId::new(),
            cidr: IpCidr {
                addr: "10.0.0.0".parse().unwrap(),
                prefix: 8,
            },
            ports: PortRange { lo: 0, hi: 65535 },
            interface: "eth0".to_string(),
            direction: crate::types::L4Direction::Outbound,
            capability: crate::types::L4Capability::Inject,
            inject_rate: RateCap {
                pps: 100,
                burst: 100,
            },
            source: L4ScopeSource::Config,
        }
    }

    /// SEC-2 — with `allow_agent_widen` false (the default), a runtime `l4.scope.add`
    /// over the bus is refused with a typed [`L4GuardError::ScopeWideningDisabled`]
    /// and adds nothing; the operator's config-declared scope still loads and
    /// remains the only entry.
    #[test]
    fn scope_add_refused_when_widen_disabled() {
        use crate::guard::L4GuardError;

        // Default config ⇒ allow_agent_widen is false; one operator-declared entry.
        let cfg = L4Config {
            scope: vec![config_declared_entry()],
            ..L4Config::default()
        };
        assert!(!cfg.allow_agent_widen, "the default must be deny (false)");

        let (reg, guard, _s) = registered(&cfg);
        let store = MemFlowStore::new();
        let client = StubClient;
        let core_guard = StdGuard::default();
        let h = host(&store, &client, &core_guard);

        // The config-declared entry loaded regardless of the flag.
        assert_eq!(guard.list_scope().len(), 1, "config scope must load");

        // A runtime add is refused with the typed refusal, and adds nothing.
        let err = reg
            .command("l4.scope.add")
            .expect("l4.scope.add registered")
            .invoke(scope_add_params(), &h)
            .expect_err("runtime scope widening must be refused when disabled");
        let typed = err
            .downcast_ref::<L4GuardError>()
            .unwrap_or_else(|| panic!("want a typed L4GuardError, got {err:?}"));
        assert_eq!(*typed, L4GuardError::ScopeWideningDisabled);

        // No entry was added: only the operator's config entry remains, usable.
        let scope = guard.list_scope();
        assert_eq!(scope.len(), 1, "a refused add must not widen the scope");
        assert_eq!(scope[0].cidr.prefix, 8, "the config entry still stands");
    }

    /// With `allow_agent_widen` true (operator opt-in), a runtime `l4.scope.add`
    /// behaves as before: it succeeds and the entry is listed.
    #[test]
    fn scope_add_allowed_when_widen_enabled() {
        let cfg = L4Config {
            allow_agent_widen: true,
            ..L4Config::default()
        };
        let (reg, guard, _s) = registered(&cfg);
        let store = MemFlowStore::new();
        let client = StubClient;
        let core_guard = StdGuard::default();
        let h = host(&store, &client, &core_guard);

        assert!(guard.list_scope().is_empty(), "deny-by-default to start");

        let added = reg
            .command("l4.scope.add")
            .expect("l4.scope.add registered")
            .invoke(scope_add_params(), &h)
            .expect("l4.scope.add must succeed when widening is enabled");
        let Value::Str(id) = added else {
            panic!("l4.scope.add must return the entry id");
        };
        assert!(!id.is_empty());

        let listed = reg
            .command("l4.scope.list")
            .unwrap()
            .invoke(Params::default(), &h)
            .expect("l4.scope.list ok");
        let Value::Array(entries) = listed else {
            panic!("l4.scope.list must return an array");
        };
        assert_eq!(entries.len(), 1, "the added entry must be listed");
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
            packets: std::collections::VecDeque::from(vec![L4Packet {
                dir: L4Direction::Outbound,
                timestamp: std::time::SystemTime::now(),
                bytes: vec![0u8; 33],
                decoded: PacketSummary {
                    layers: vec!["IPv4".into(), "UDP".into()],
                    length: 33,
                },
                injected: true,
            }]),
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

    /// An `l4.inject` params object (spec + dst + interface). The gate short-circuits
    /// before these are parsed, so a representative-but-minimal set suffices.
    fn inject_params() -> Params {
        let mut m = BTreeMap::new();
        m.insert("spec".to_string(), craft_spec());
        m.insert("dst".to_string(), Value::Str("127.0.0.1".into()));
        m.insert("interface".to_string(), Value::Str("lo0".into()));
        Params::new(m)
    }

    /// Amended M5 Task 13 (AC17): with the module enabled but the startup capability
    /// probe reporting no privilege, the module STILL registers its full surface; the
    /// pure/read verbs still work (`l4.interfaces`), but the wire-touching verbs
    /// (`l4.inject`) return a typed `L4Unavailable` naming the missing capability —
    /// without a panic and without re-probing.
    #[test]
    fn enabled_no_priv_wire_unavailable() {
        use crate::backend::L4Error;

        let cfg = L4Config {
            enabled: true,
            ..L4Config::default()
        };
        let privilege = L4Privilege {
            capture_inject: Some("missing CAP_NET_RAW / /dev/bpf access".into()),
            intercept: Some("missing CAP_NET_ADMIN".into()),
        };
        let module = L4Module::with_privilege(&cfg, privilege);
        let mut reg = Registry::new();
        reg.add_plugin(Box::new(module));

        // The full surface is registered (an honest, drivable surface for the operator
        // who opted in), wire verbs included.
        assert!(reg.command("l4.inject").is_some(), "l4.inject registered");
        assert!(
            reg.command("l4.interfaces").is_some(),
            "l4.interfaces registered"
        );
        assert!(reg.command("l4.craft").is_some(), "l4.craft registered");

        let store = MemFlowStore::new();
        let client = StubClient;
        let guard = StdGuard::default();
        let h = host(&store, &client, &guard);

        // A pure/read verb works regardless of privilege.
        reg.command("l4.interfaces")
            .expect("l4.interfaces registered")
            .invoke(Params::default(), &h)
            .expect("l4.interfaces works without privilege");

        // A wire verb fails closed with the specific capability reason.
        let err = reg
            .command("l4.inject")
            .expect("l4.inject registered")
            .invoke(inject_params(), &h)
            .unwrap_err();
        let l4 = err
            .downcast_ref::<L4Error>()
            .unwrap_or_else(|| panic!("want a typed L4Error, got {err:?}"));
        match l4 {
            L4Error::Unavailable(why) => assert!(
                why.contains("CAP_NET_RAW") || why.contains("/dev/bpf"),
                "the reason must name the missing capability, got {why:?}"
            ),
            other => panic!("want L4Error::Unavailable, got {other:?}"),
        }
    }

    /// The real startup probe is defensive: it never panics, whatever the platform
    /// or privilege. (Behaviour is platform-dependent; this only pins "no panic".)
    #[test]
    fn probe_does_not_panic() {
        let _ = L4Privilege::probe();
    }
}
