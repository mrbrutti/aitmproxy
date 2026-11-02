//! `l4.scope.add` / `.remove` / `.list` — manage the deny-by-default L4 scope.
//!
//! Sensitivity: **manages scope**. These commands do not touch the wire; they edit
//! the [`L4Guard`](crate::guard::L4Guard) scope list the wire commands (M5 Task 10)
//! later check against. `scope.add` is the single explicit escape hatch that brings
//! a CIDR + port + interface + direction + capability into play (deny-by-default);
//! `scope.remove` reverts a target to denied. No injection is authorized here — no
//! [`L4Permit`](crate::guard::L4Permit) is minted.

use std::sync::Arc;

use aitm_core::{
    Command, CommandHost, ParamDef, ParamSchema, Params, Sensitivity, TypeDesc, Value,
};

use crate::guard::{L4Guard, ANY_INTERFACE};
use crate::types::{L4ScopeEntry, L4ScopeId, L4ScopeSource, RateCap};

/// Proof that `l4.scope.add` was dispatched on a **trusted-control** path (spec §3,
/// fork (ii)): the MCP server's `Frontend::Operator` or the CLI's `Frontend::Cli`.
///
/// A zero-sized token [`L4Guard::add_operator_scope`] demands. It proves exactly
/// one thing — that the call reached [`ScopeAdd::invoke`] with
/// `caller_is_trusted_control()` true — and nothing about the human: the
/// confirmation step itself is the dispatcher's (the MCP server's
/// confirm-over-the-wire handshake, the CLI's `Confirmer`), which runs before
/// `invoke` is ever called. Its only constructor is private to this module and the
/// type is crate-private, so Rhai, the PoC `l4:` step and every other in-process
/// caller cannot name a value of it and cannot reach the ungated path: the compiler
/// enforces it, not a source grep.
pub(crate) struct OperatorConfirmed(());

impl OperatorConfirmed {
    /// Mint the proof. Reachable only from this module (see the type docs); the unit
    /// tests below are inside it, so no test-only constructor exists.
    pub(in crate::commands::scope) fn new() -> Self {
        Self(())
    }
}

/// The wide-range threshold the confirm prompt warns below: a prefix shorter than
/// `/16` (IPv4) or `/48` (IPv6) covers more than one operator usually means.
fn wide_range_warning(cidr: &crate::types::IpCidr) -> Option<String> {
    let floor: u8 = if cidr.addr.is_ipv4() { 16 } else { 48 };
    (cidr.prefix < floor).then(|| format!(" WARNING: /{} is a wide range.", cidr.prefix))
}

/// The operator confirm prompt for a parsed entry (spec §3): capability, cidr, ports
/// (`all ports` for the full range), interface, direction and the inject rate
/// (`inject refused (rate 0)` when 0), and the denylist rule. It says nothing about
/// *how* to confirm: the dispatcher that shows it (the MCP server's
/// confirm-over-the-wire reply, the CLI `Confirmer`) explains its own handshake, and
/// under policy `ask` the same text is the agent approval card, where a "re-issue
/// with `_confirm`" instruction would mislead the operator.
fn confirm_prompt_for(entry: &L4ScopeEntry) -> String {
    let ports = if entry.ports.is_any() {
        "all ports".to_string()
    } else {
        format!("ports {}", super::ports_to_string(&entry.ports))
    };
    let rate = if entry.inject_rate.pps == 0 {
        "inject refused (rate 0)".to_string()
    } else {
        format!(
            "inject rate {}pps/{}burst",
            entry.inject_rate.pps, entry.inject_rate.burst
        )
    };
    let mut prompt = format!(
        "Confirm l4.scope.add: {} scope for {} {ports} on {} ({}), {rate}. A runtime entry \
         never lifts the dangerous-destination denylist.",
        super::capability_to_string(entry.capability),
        super::cidr_to_string(&entry.cidr),
        entry.interface,
        super::direction_to_string(entry.direction),
    );
    if let Some(warning) = wide_range_warning(&entry.cidr) {
        prompt.push_str(&warning);
    }
    prompt
}

/// `l4.scope.add {..}` → add a scope entry; returns its minted id.
pub struct ScopeAdd {
    guard: Arc<L4Guard>,
}

impl ScopeAdd {
    /// A command over the shared guard. The SEC-2 widen gate (reading the shared
    /// [`L4AgentGates`](crate::gates::L4AgentGates) **widen** gate, so
    /// `l4.agent.set {capability:"widen"}` governs it live) and the forced
    /// `source = Runtime` both live in the guard ([`L4Guard::add_runtime_scope`] for
    /// an agent, [`L4Guard::add_operator_scope`] for a confirmed operator), so the
    /// command is a thin wrapper and carries no gate of its own.
    pub fn new(guard: Arc<L4Guard>) -> Self {
        Self { guard }
    }
}

impl Command for ScopeAdd {
    fn name(&self) -> &str {
        "l4.scope.add"
    }

    fn sensitivity(&self) -> Sensitivity {
        // Widens L4 authority (the one escape hatch out of deny-by-default) — gated
        // like `scope.add` / `ca.install`.
        Sensitivity::Sensitive
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Add an entry to the deny-by-default L4 scope (CIDR, ports, interface, \
                          direction, capability, injection rate). The single escape hatch that \
                          brings a target into play."
                .into(),
            params: vec![
                ParamDef {
                    name: "cidr".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "`addr/prefix` (e.g. `127.0.0.1/32`); a bare address ⇒ host."
                        .into(),
                },
                ParamDef {
                    name: "interface".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description:
                        "The interface this entry covers (e.g. `lo0`), or `*` for any interface."
                            .into(),
                },
                ParamDef {
                    name: "direction".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "`inbound` or `outbound`.".into(),
                },
                ParamDef {
                    name: "capability".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "`capture`, `inject`, or `intercept`.".into(),
                },
                ParamDef {
                    name: "ports".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "`lo-hi`, a single port, or `*`/omitted ⇒ any.".into(),
                },
                ParamDef {
                    name: "inject_rate_pps".into(),
                    ty: TypeDesc::Int,
                    required: false,
                    description: "Per-entry injection rate (packets/sec); 0 ⇒ refuse. Default 0."
                        .into(),
                },
                ParamDef {
                    name: "inject_rate_burst".into(),
                    ty: TypeDesc::Int,
                    required: false,
                    description: "Per-entry injection burst; default = `inject_rate_pps`.".into(),
                },
            ],
            result: TypeDesc::Str,
        }
    }

    /// Always `Some` (spec §3): with valid arguments it summarises the entry, with
    /// missing or invalid ones it names the error — so `tools/list`, which probes
    /// with no arguments, reports `confirmable: true` and every UI renders its add
    /// control. The MCP server offers the handshake only to `Frontend::Operator`
    /// and the CLI asks its `Confirmer`; an agent is never handed one.
    fn confirm_prompt(&self, args: &Params) -> Option<String> {
        Some(match entry_from_params(args) {
            Ok(entry) => confirm_prompt_for(&entry),
            Err(e) => format!("Confirm l4.scope.add: add an L4 scope entry ({e:#})."),
        })
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let entry = entry_from_params(&args)?;
        let id = if host.caller_is_trusted_control() {
            // A present human (operator over the bus, or the CLI) has already been
            // asked through `confirm_prompt` — the server's confirm-over-the-wire
            // handshake or the CLI `Confirmer` — so the agent **widen** gate does
            // not apply (spec §3, fork (ii)). The proof is mintable only here.
            self.guard
                .add_operator_scope(entry, OperatorConfirmed::new())
        } else {
            // Everyone else (an agent over MCP, including one approved under `Ask`):
            // deny-by-default widening is enforced in the guard. `add_runtime_scope`
            // refuses with the typed `L4GuardError::ScopeWideningDisabled` (adding
            // nothing) when the shared **widen** gate is off. Keeping the gate in the
            // guard (not this command) is SEC-2: no second in-process caller of the
            // shared guard can bypass it, and an operator `l4.agent.set` flips the
            // very gate the guard reads.
            self.guard
                .add_runtime_scope(entry)
                .map_err(anyhow::Error::new)?
        };
        Ok(Value::Str(super::scope_id_to_string(id)))
    }
}

/// `l4.scope.remove {id}` → remove the entry with that id; returns whether one was.
pub struct ScopeRemove {
    guard: Arc<L4Guard>,
}

impl ScopeRemove {
    /// A command over the shared guard.
    pub fn new(guard: Arc<L4Guard>) -> Self {
        Self { guard }
    }
}

impl Command for ScopeRemove {
    fn name(&self) -> &str {
        "l4.scope.remove"
    }

    fn sensitivity(&self) -> Sensitivity {
        // Narrows authority: mutating, but safe-ward (never touches the wire).
        Sensitivity::Write
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Remove an L4 scope entry by id (reverts that target to deny-by-default)."
                .into(),
            params: vec![ParamDef {
                name: "id".into(),
                ty: TypeDesc::Str,
                required: true,
                description: "The scope entry id to remove.".into(),
            }],
            result: TypeDesc::Bool,
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let id = super::scope_id_from_str(args.get_str("id")?)?;
        Ok(Value::Bool(self.guard.remove_scope(id)))
    }
}

/// `l4.scope.list` → the current scope entries.
pub struct ScopeList {
    guard: Arc<L4Guard>,
}

impl ScopeList {
    /// A command over the shared guard.
    pub fn new(guard: Arc<L4Guard>) -> Self {
        Self { guard }
    }
}

impl Command for ScopeList {
    fn name(&self) -> &str {
        "l4.scope.list"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "List the current L4 scope entries (read-only).".into(),
            params: vec![],
            result: TypeDesc::Array(Box::new(TypeDesc::Object(super::scope_entry_fields()))),
        }
    }

    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        Ok(Value::Array(
            self.guard
                .list_scope()
                .iter()
                .map(super::scope_entry_to_value)
                .collect(),
        ))
    }
}

/// The longest interface name the OS accepts (`IFNAMSIZ` is 16 including the NUL).
const IFNAMSIZ_MAX: usize = 15;

/// Accept an `interface` only if it is an OS interface name,
/// `^[A-Za-z0-9._:-]{1,15}$`, or exactly the [`ANY_INTERFACE`] wildcard `"*"` (the
/// D9.5 rule the guard matches: an entry on `"*"` covers a target on any interface,
/// which is how an unprivileged socket client such as the stream lane is authorised;
/// the operator declares a destination, not a NIC). `"**"`, `"*x"` and every other
/// string with a `*` stay refused. Both add paths (operator-confirmed and agent)
/// build their entry through [`entry_from_params`], so both are covered; a rejected
/// value is echoed escaped (`{:?}`), never raw, so a control or ANSI sequence cannot
/// reach a terminal or a UI through the error text.
fn validate_interface(s: &str) -> anyhow::Result<String> {
    if s == ANY_INTERFACE {
        return Ok(s.to_string());
    }
    let name_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-');
    if s.is_empty() || s.len() > IFNAMSIZ_MAX || !s.chars().all(name_char) {
        anyhow::bail!(
            "param `interface` must be `*` (any interface) or 1-15 characters of \
             [A-Za-z0-9._:-] (IFNAMSIZ), got {s:?}"
        );
    }
    Ok(s.to_string())
}

/// Build a scope entry from the flattened, human-friendly `scope.add` params.
fn entry_from_params(args: &Params) -> anyhow::Result<L4ScopeEntry> {
    let cidr = super::parse_cidr(args.get_str("cidr")?)?;
    let interface = validate_interface(args.get_str("interface")?)?;
    let direction = super::parse_direction(args.get_str("direction")?)?;
    let capability = super::parse_capability(args.get_str("capability")?)?;
    let ports = match args.get("ports") {
        Some(Value::Str(s)) => super::parse_ports(s)?,
        Some(other) => anyhow::bail!("param `ports` must be a string, got {other:?}"),
        None => super::parse_ports("")?,
    };
    let pps = match args.get("inject_rate_pps") {
        Some(_) => u32::try_from(args.get_int("inject_rate_pps")?)
            .map_err(|_| anyhow::anyhow!("`inject_rate_pps` must be a non-negative integer"))?,
        None => 0,
    };
    let burst = match args.get("inject_rate_burst") {
        Some(_) => u32::try_from(args.get_int("inject_rate_burst")?)
            .map_err(|_| anyhow::anyhow!("`inject_rate_burst` must be a non-negative integer"))?,
        None => pps,
    };
    Ok(L4ScopeEntry {
        id: L4ScopeId::new(),
        cidr,
        ports,
        interface,
        direction,
        capability,
        inject_rate: RateCap { pps, burst },
        // Provenance is set here for completeness, but the guard re-forces
        // `source = Runtime` at the boundary (both add paths end in its private
        // `push_runtime`) — a runtime add, operator-confirmed or not, can never mint
        // operator (`Config`) provenance and so can never lift the denylist.
        source: L4ScopeSource::Runtime,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::L4Config;
    use crate::types::{IpCidr, L4Capability, L4Direction, PortRange};

    struct StubClient;
    impl aitm_core::ProxyClient for StubClient {
        fn send(
            &self,
            _req: aitm_core::HttpRequest,
        ) -> futures::future::BoxFuture<'_, anyhow::Result<aitm_core::HttpFlow>> {
            Box::pin(async { anyhow::bail!("stub client") })
        }
    }

    fn entry(ports: PortRange, source: L4ScopeSource) -> L4ScopeEntry {
        L4ScopeEntry {
            id: L4ScopeId::new(),
            cidr: IpCidr {
                addr: "127.0.0.1".parse().expect("literal v4 address"),
                prefix: 32,
            },
            ports,
            interface: "lo0".to_string(),
            direction: L4Direction::Inbound,
            capability: L4Capability::Capture,
            inject_rate: RateCap { pps: 0, burst: 0 },
            source,
        }
    }

    /// Plan Task A5 (L4PAR-AC5, the `source` half): `l4.scope.list` labels each
    /// entry's provenance — `"config"` for an operator config-block entry, `"runtime"`
    /// for one added over the bus — in list order, so UIs can label them.
    #[test]
    fn scope_list_reports_source() {
        let cfg = L4Config {
            scope: vec![entry(
                PortRange { lo: 9000, hi: 9999 },
                L4ScopeSource::Config,
            )],
            ..L4Config::default()
        };
        let guard = Arc::new(L4Guard::new(&cfg));
        // Test-only push (no widen gate): the provenance is whatever the entry says.
        guard
            .add_scope(entry(
                PortRange { lo: 9100, hi: 9199 },
                L4ScopeSource::Runtime,
            ))
            .expect("test-only add_scope never refuses");

        let mem = aitm_core::MemFlowStore::new();
        let client = StubClient;
        let core = aitm_core::StdGuard::default();
        let host = CommandHost::new(&mem, &client, &core, None);

        let listed = ScopeList::new(guard)
            .invoke(Params::default(), &host)
            .expect("l4.scope.list ok");
        let Value::Array(entries) = listed else {
            panic!("l4.scope.list must return an array, got {listed:?}");
        };
        assert_eq!(entries.len(), 2);

        let field = |i: usize, key: &str| -> Option<Value> {
            let Value::Object(obj) = &entries[i] else {
                panic!("a scope entry must be an object, got {:?}", entries[i]);
            };
            obj.get(key).cloned()
        };
        assert_eq!(field(0, "ports"), Some(Value::Str("9000-9999".into())));
        assert_eq!(field(0, "source"), Some(Value::Str("config".into())));
        assert_eq!(field(1, "ports"), Some(Value::Str("9100-9199".into())));
        assert_eq!(field(1, "source"), Some(Value::Str("runtime".into())));
    }

    /// The `l4.scope.list` result schema declares `source` as a required string, so
    /// `tools/list` consumers learn the field without reading a live entry.
    #[test]
    fn scope_list_schema_declares_source() {
        let cfg = L4Config::default();
        let schema = ScopeList::new(Arc::new(L4Guard::new(&cfg))).schema();
        let TypeDesc::Array(elem) = schema.result else {
            panic!(
                "l4.scope.list result must be an array, got {:?}",
                schema.result
            );
        };
        let TypeDesc::Object(fields) = *elem else {
            panic!("l4.scope.list elements must be objects, got {elem:?}");
        };
        let source = fields
            .iter()
            .find(|f| f.name == "source")
            .unwrap_or_else(|| {
                panic!(
                    "scope entry fields must list `source`; got {:?}",
                    fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()
                )
            });
        assert!(
            matches!(source.ty, TypeDesc::Str),
            "`source` must be a Str, got {:?}",
            source.ty
        );
        assert!(source.required, "`source` must be required");
        assert!(
            source.description.contains("config") && source.description.contains("runtime"),
            "the description names both provenances, got {}",
            source.description
        );
    }

    fn params(pairs: &[(&str, Value)]) -> Params {
        Params::new(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), v.clone()))
                .collect(),
        )
    }

    /// The L4PAR-AC5 entry without `ports` (the base every prompt test extends);
    /// the one ports case adds `("ports", "9100-9199")` explicitly.
    fn ac5_params() -> Vec<(&'static str, Value)> {
        vec![
            ("cidr", Value::Str("127.0.0.1/32".into())),
            ("interface", Value::Str("lo0".into())),
            ("direction", Value::Str("inbound".into())),
            ("capability", Value::Str("capture".into())),
        ]
    }

    fn scope_add() -> ScopeAdd {
        ScopeAdd::new(Arc::new(L4Guard::new(&L4Config::default())))
    }

    /// Security panel (unit (a')): `interface` is an OS interface name, so both add
    /// paths (operator-confirmed and agent) accept only `^[A-Za-z0-9._:-]{1,15}$`
    /// (IFNAMSIZ). Empty, over-long, control and ANSI-escape names are refused with
    /// an error naming the param and the rule; real names pass through verbatim.
    #[test]
    fn interface_is_validated() {
        let with_interface = |iface: &str| -> anyhow::Result<L4ScopeEntry> {
            let mut p = ac5_params();
            p.retain(|(k, _)| *k != "interface");
            p.push(("interface", Value::Str(iface.to_string())));
            entry_from_params(&params(&p))
        };

        let err = with_interface("").expect_err("an empty interface is refused");
        assert_eq!(
            err.to_string(),
            "param `interface` must be `*` (any interface) or 1-15 characters of \
             [A-Za-z0-9._:-] (IFNAMSIZ), got \"\""
        );
        let err = with_interface("abcdefghijklmnop").expect_err("16 characters is refused");
        assert_eq!(
            err.to_string(),
            "param `interface` must be `*` (any interface) or 1-15 characters of \
             [A-Za-z0-9._:-] (IFNAMSIZ), got \"abcdefghijklmnop\""
        );
        let err = with_interface("lo0\n").expect_err("a control character is refused");
        assert_eq!(
            err.to_string(),
            "param `interface` must be `*` (any interface) or 1-15 characters of \
             [A-Za-z0-9._:-] (IFNAMSIZ), got \"lo0\\n\""
        );
        let err = with_interface("\x1b[31mlo0").expect_err("an ANSI escape is refused");
        assert_eq!(
            err.to_string(),
            "param `interface` must be `*` (any interface) or 1-15 characters of \
             [A-Za-z0-9._:-] (IFNAMSIZ), got \"\\u{1b}[31mlo0\""
        );
        assert!(with_interface("lo 0").is_err(), "a space is refused");
        assert!(with_interface("en0/1").is_err(), "a slash is refused");
        assert!(with_interface("**").is_err(), "`**` is not the wildcard");
        assert!(with_interface("*x").is_err(), "`*x` is not the wildcard");
        assert!(with_interface("x*").is_err(), "`x*` is not the wildcard");
        assert!(
            with_interface(" *").is_err(),
            "a padded `*` is not the wildcard"
        );
        let any = with_interface(ANY_INTERFACE).expect("`*` is the D9.5 wildcard");
        assert_eq!(any.interface, ANY_INTERFACE);

        for ok in [
            "lo0",
            "en0",
            "utun3",
            "br-1",
            "eth0.100",
            "wg_0:1",
            "abcdefghijklmno",
        ] {
            let entry = with_interface(ok).unwrap_or_else(|e| panic!("`{ok}` is accepted: {e}"));
            assert_eq!(entry.interface, ok);
        }
    }

    /// Scanner v2 D7/D9.5 (T7 security re-review): the inject entry the gate text
    /// tells an operator to add (`interface "*", direction outbound, <ip>/32,
    /// capability inject`) must be creatable over the bus, not only from the config
    /// file. `l4.scope.add` on a trusted-control host with `interface: "*"` mints an
    /// entry whose interface is the wildcard; `"**"` and `"*x"` are refused by the
    /// same verb with the error naming the param and the rule.
    #[test]
    fn scope_add_accepts_the_any_interface_wildcard_over_the_bus() {
        let guard = Arc::new(L4Guard::new(&L4Config {
            enabled: true,
            ..L4Config::default()
        }));
        let cmd = ScopeAdd::new(Arc::clone(&guard));
        let mem = aitm_core::MemFlowStore::new();
        let client = StubClient;
        let core = aitm_core::StdGuard::default();
        let host =
            CommandHost::new(&mem, &client, &core, None).with_frontend(aitm_core::Frontend::Cli);
        let args_for = |iface: &str| -> Params {
            let mut p = ac5_params();
            p.retain(|(k, _)| *k != "interface" && *k != "capability" && *k != "direction");
            p.push(("interface", Value::Str(iface.to_string())));
            p.push(("direction", Value::Str("outbound".into())));
            p.push(("capability", Value::Str("inject".into())));
            params(&p)
        };

        let id = cmd
            .invoke(args_for(ANY_INTERFACE), &host)
            .expect("`*` is accepted over the bus");
        assert!(
            matches!(id, Value::Str(_)),
            "scope.add returns the minted id"
        );
        let added = guard
            .list_scope()
            .into_iter()
            .find(|e| e.interface == ANY_INTERFACE)
            .expect("the wildcard entry is in the guard's scope");
        assert_eq!(added.direction, L4Direction::Outbound);

        for bad in ["**", "*x"] {
            let err = cmd
                .invoke(args_for(bad), &host)
                .expect_err("only the exact wildcard is accepted");
            assert!(
                err.to_string()
                    .starts_with("param `interface` must be `*` (any interface)"),
                "{bad}: {err}"
            );
        }
        assert_eq!(
            guard
                .list_scope()
                .iter()
                .filter(|e| e.interface.contains('*'))
                .count(),
            1,
            "the refused names added nothing"
        );
    }

    /// Spec §3 / plan A6: `confirm_prompt` is `Some` even with empty args, so
    /// `tools/list` (which probes with `Params::default()`) reports `confirmable:
    /// true` and every UI renders its scope-add control.
    #[test]
    fn confirm_prompt_some_for_empty_args() {
        let prompt = scope_add()
            .confirm_prompt(&Params::default())
            .expect("l4.scope.add is always confirmable");
        // The verb, the missing-arg error, and nothing else: the handshake itself is
        // the dispatcher's to explain (MCP server / CLI confirmer), so the prompt
        // carries no "re-issue with `_confirm`" sentence that would mislead when the
        // same text is shown on an agent approval card under policy `ask`.
        assert_eq!(
            prompt,
            "Confirm l4.scope.add: add an L4 scope entry (missing required param `cidr`)."
        );
    }

    /// L4PAR-AC5: with the AC5 arguments (the base plus `ports: 9100-9199`) the prompt
    /// summarises the entry — the five AC5 strings (cidr, ports, interface, direction,
    /// capability), the rate, and the denylist rule — and ends there: no "re-issue
    /// with `_confirm`" sentence (the dispatcher explains its own handshake).
    #[test]
    fn confirm_prompt_summarises_entry() {
        let mut p = ac5_params();
        p.push(("ports", Value::Str("9100-9199".into())));
        let prompt = scope_add()
            .confirm_prompt(&params(&p))
            .expect("valid args are confirmable");
        assert_eq!(
            prompt,
            "Confirm l4.scope.add: capture scope for 127.0.0.1/32 ports 9100-9199 on lo0 \
             (inbound), inject refused (rate 0). A runtime entry never lifts the \
             dangerous-destination denylist."
        );
    }

    /// L4PAR-AC5 (unit): ports omitted ⇒ `all ports`; `inject_rate_pps: 0` ⇒
    /// `inject refused (rate 0)`; a non-zero rate is spelled out; a prefix shorter
    /// than /16 (IPv4) or /48 (IPv6) appends the wide-range warning, /16 and /48
    /// themselves do not.
    #[test]
    fn confirm_prompt_variants() {
        let cmd = scope_add();
        let prompt_for = |overrides: &[(&str, Value)]| -> String {
            let mut p = ac5_params();
            p.retain(|(k, _)| !overrides.iter().any(|(ok, _)| ok == k));
            p.extend(overrides.iter().cloned());
            cmd.confirm_prompt(&params(&p))
                .expect("valid args are confirmable")
        };

        // Ports omitted.
        let p = prompt_for(&[]);
        assert!(p.contains(" all ports on lo0 "), "got: {p}");
        assert!(!p.contains("0-65535"), "got: {p}");

        // Rate 0 (explicit) ⇒ refused.
        let p = prompt_for(&[
            ("inject_rate_pps", Value::Int(0)),
            ("inject_rate_burst", Value::Int(0)),
        ]);
        assert!(p.contains("inject refused (rate 0)"), "got: {p}");

        // A real rate is spelled out as pps/burst.
        let p = prompt_for(&[
            ("inject_rate_pps", Value::Int(50)),
            ("inject_rate_burst", Value::Int(200)),
        ]);
        assert!(p.contains("inject rate 50pps/200burst"), "got: {p}");
        assert!(!p.contains("refused"), "got: {p}");

        // Wide IPv4 prefix ⇒ warning; /16 exactly does not warn.
        let p = prompt_for(&[("cidr", Value::Str("10.0.0.0/8".into()))]);
        assert!(p.contains("WARNING: /8 is a wide range"), "got: {p}");
        assert!(
            p.ends_with("dangerous-destination denylist. WARNING: /8 is a wide range."),
            "got: {p}"
        );
        let p = prompt_for(&[("cidr", Value::Str("10.0.0.0/16".into()))]);
        assert!(!p.contains("WARNING"), "got: {p}");

        // Wide IPv6 prefix ⇒ warning; /48 exactly does not warn.
        let p = prompt_for(&[("cidr", Value::Str("2001:db8::/32".into()))]);
        assert!(p.contains("WARNING: /32 is a wide range"), "got: {p}");
        let p = prompt_for(&[("cidr", Value::Str("2001:db8::/48".into()))]);
        assert!(!p.contains("WARNING"), "got: {p}");

        // Invalid args still confirmable, naming the error (so tools/list is static).
        let p = cmd
            .confirm_prompt(&params(&[("cidr", Value::Str("nonsense".into()))]))
            .expect("invalid args are still confirmable");
        assert!(
            p.starts_with(
                "Confirm l4.scope.add: add an L4 scope entry (bad CIDR address `nonsense`"
            ),
            "got: {p}"
        );
    }

    /// L4PAR-AC7 (plan A6) — the operator-confirmed path (`add_operator_scope`)
    /// skips the widen gate but, like every runtime add, funnels through
    /// `push_runtime`: the stored entry is `Runtime` even when the caller passed
    /// `Config`, so an operator runtime add of the cloud-metadata address never lifts
    /// the dangerous-destination denylist, `dangerous_dst_override` notwithstanding.
    /// Lives here because only this module can mint the `OperatorConfirmed` proof.
    #[test]
    fn operator_scope_cannot_lift_denylist() {
        use crate::guard::L4GuardError;
        use crate::types::{L4Action, L4Proto, L4Target};

        let cfg = L4Config {
            dangerous_dst_override: true,
            ..L4Config::default()
        };
        assert!(
            !cfg.allow_agent_widen,
            "widen stays off: the operator path skips it"
        );
        let guard = L4Guard::new(&cfg);

        let spoofed = L4ScopeEntry {
            id: L4ScopeId::new(),
            cidr: IpCidr {
                addr: "169.254.169.254".parse().expect("literal v4 address"),
                prefix: 32,
            },
            ports: PortRange::ANY,
            interface: "eth0".to_string(),
            direction: L4Direction::Outbound,
            capability: L4Capability::Inject,
            inject_rate: RateCap {
                pps: 100,
                burst: 100,
            },
            source: L4ScopeSource::Config,
        };
        let id = guard.add_operator_scope(spoofed, OperatorConfirmed::new());

        let stored = guard.list_scope();
        assert_eq!(stored.len(), 1, "the operator add stored exactly one entry");
        assert_eq!(stored[0].id, id);
        assert_eq!(
            stored[0].source,
            L4ScopeSource::Runtime,
            "an operator runtime add is stored as Runtime, never Config"
        );
        let target = L4Target {
            interface: "eth0".to_string(),
            direction: L4Direction::Outbound,
            dst: Some("169.254.169.254".parse().expect("literal v4 address")),
            dst_port: Some(80),
            proto: L4Proto::Tcp,
        };
        assert_eq!(
            guard.check(L4Action::Inject, &target).unwrap_err(),
            L4GuardError::DangerousDestinationBlocked("169.254.169.254".into()),
            "an operator runtime add must not lift the denylist"
        );
    }
}
