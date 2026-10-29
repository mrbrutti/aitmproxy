//! `l4.inject` — craft a spec and inject it to a target as a guarded, bounded,
//! rate-capped batch (M5 Task 10).
//!
//! Sensitivity: **guarded (`Inject`)**. This is a wire-touching command: it puts
//! crafted bytes on the network. It is gated **twice**, in order:
//!
//! 1. **Primary — the L4 guard.** [`L4Guard::check(Inject)`](crate::guard::L4Guard::check)
//!    applies scope + the dangerous-destination denylist + rate/size/count and mints
//!    the injection [`L4Permit`](crate::guard::L4Permit) that
//!    [`send_on_wire`](crate::wire::send_on_wire) — the single choke point — demands.
//!    Deny-by-default: an empty or non-matching scope returns `OutOfL4Scope` **before**
//!    anything reaches the wire (AC1/AC2). The L4 guard is checked first so that the
//!    refusal an operator sees is the specific L4 one.
//! 2. **Defense in depth — the core guard.** [`CommandHost::guard().check_active`]
//!    re-gates the destination against the proxy-wide scope/rate/concurrency guard,
//!    so an L4 target must also be an in-scope engagement host.
//!
//! Every write goes through [`send_on_wire`](crate::wire::send_on_wire); the batch
//! threads one permit, so the per-call count + size budget bounds the whole batch.
//!
//! [`CommandHost::guard().check_active`]: aitm_core::ScopeRateGuard::check_active

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

use aitm_core::{
    Command, CommandHost, ParamDef, ParamSchema, Params, Sensitivity, TypeDesc, Value,
};

use crate::backend::CaptureInjectBackend;
use crate::craft::PacketSpec;
use crate::flow::{L4Bind, L4Flow, L4FlowId, L4FlowKind, L4FlowStore, L4Meta, L4Packet};
use crate::guard::{L4Guard, L4GuardError};
use crate::types::{L4Action, L4Capability, L4Direction, L4Target};
use crate::wire::send_on_wire;

/// `l4.inject {spec, dst, interface, port?, count?}` → inject a crafted spec to a
/// target as a bounded, rate-capped batch; returns the recorded flow id + how many
/// packets reached the wire.
pub struct Inject {
    guard: Arc<L4Guard>,
    store: Arc<dyn L4FlowStore>,
    backend: Arc<dyn CaptureInjectBackend>,
}

impl Inject {
    /// A command over the shared guard, flow store, and wire backend.
    pub fn new(
        guard: Arc<L4Guard>,
        store: Arc<dyn L4FlowStore>,
        backend: Arc<dyn CaptureInjectBackend>,
    ) -> Self {
        Self {
            guard,
            store,
            backend,
        }
    }
}

impl Command for Inject {
    fn name(&self) -> &str {
        "l4.inject"
    }

    fn sensitivity(&self) -> Sensitivity {
        // Writes crafted packets to the wire.
        Sensitivity::Sensitive
    }

    /// The operator confirm-over-the-wire prompt (spec §2.4): a summary of exactly
    /// what will hit the wire. `None` — no confirmation offered, so no token is minted
    /// — when the guard would refuse this target (out of scope, denylisted, or rate
    /// disabled); `invoke` then surfaces the specific typed refusal (AC6:
    /// out-of-scope is refused **before** any token is minted). Only the operator
    /// role is offered this handshake by the server.
    fn confirm_prompt(&self, args: &Params) -> Option<String> {
        let spec = super::parse_packet_spec(super::require(args, "spec").ok()?).ok()?;
        let dst: IpAddr = args.get_str("dst").ok()?.parse().ok()?;
        let interface = args.get_str("interface").ok()?.to_string();
        let dst_port = match args.get("port") {
            Some(_) => Some(u16::try_from(args.get_int("port").ok()?).ok()?),
            None => None,
        };
        let count = match args.get("count") {
            Some(_) => u32::try_from(args.get_int("count").ok()?).ok()?,
            None => 1,
        };
        let bytes = spec.build().ok()?;
        let target = L4Target {
            interface: interface.clone(),
            direction: L4Direction::Outbound,
            dst: Some(dst),
            dst_port,
            proto: spec.transport_proto(),
        };
        // The authoritative scope / denylist / rate decision. An `Err` here (the guard
        // would refuse) means no confirmation and no token — `invoke` refuses with the
        // typed error instead.
        let permit = self.guard.check(L4Action::Inject, &target).ok()?;
        let summary = PacketSpec::summarize(&bytes);
        let entry = super::covering_scope_entry(
            &self.guard,
            &interface,
            L4Direction::Outbound,
            L4Capability::Inject,
            Some(dst),
            dst_port,
        );
        Some(super::wire_confirm_summary(
            "l4.inject",
            dst,
            dst_port,
            &interface,
            L4Direction::Outbound,
            &summary.layers,
            summary.length,
            count,
            permit.remaining(),
            entry.as_ref(),
        ))
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Inject a crafted PacketSpec to a target as a bounded, rate-capped batch. \
                          Guarded (Inject): scope + dangerous-destination denylist + rate/size/count, \
                          then the core scope/rate guard. Routes every write through the single \
                          send_on_wire choke point."
                .into(),
            params: vec![
                ParamDef {
                    name: "spec".into(),
                    ty: TypeDesc::Any,
                    required: true,
                    description: "A PacketSpec (see `l4.craft`): `{ layers: [..] }`, outermost first."
                        .into(),
                },
                ParamDef {
                    name: "dst".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "The destination IP address (e.g. `127.0.0.1`).".into(),
                },
                ParamDef {
                    name: "interface".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "The interface to inject on (e.g. `lo0`).".into(),
                },
                ParamDef {
                    name: "port".into(),
                    ty: TypeDesc::Int,
                    required: false,
                    description: "The destination port, matched against scope for TCP/UDP.".into(),
                },
                ParamDef {
                    name: "count".into(),
                    ty: TypeDesc::Int,
                    required: false,
                    description: "How many copies to send (default 1), bounded by the permit's \
                                  per-call count budget."
                        .into(),
                },
            ],
            result: TypeDesc::Object(vec![
                ParamDef {
                    name: "flow_id".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "The id of the recorded inject (`Craft`) flow.".into(),
                },
                ParamDef {
                    name: "sent".into(),
                    ty: TypeDesc::Int,
                    required: true,
                    description: "How many packets reached the wire.".into(),
                },
            ]),
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let spec = super::parse_packet_spec(super::require(&args, "spec")?)?;
        let dst: IpAddr = args
            .get_str("dst")?
            .parse()
            .map_err(|e| anyhow::anyhow!("param `dst` is not an IP address: {e}"))?;
        let interface = args.get_str("interface")?.to_string();
        let dst_port = match args.get("port") {
            Some(_) => Some(
                u16::try_from(args.get_int("port")?)
                    .map_err(|_| anyhow::anyhow!("`port` must be in 0..=65535"))?,
            ),
            None => None,
        };
        let count = match args.get("count") {
            Some(_) => u32::try_from(args.get_int("count")?)
                .map_err(|_| anyhow::anyhow!("`count` must be a non-negative integer"))?,
            None => 1,
        };

        // Build the frame once — pure and privilege-free; `Some` fields ship verbatim
        // (a forced-bad checksum survives), omitted fields auto-complete.
        let bytes = spec
            .build()
            .map_err(|e| anyhow::anyhow!("craft failed: {e}"))?;

        // C3: the guard must gate the destination actually put on the wire, not the
        // `dst` parameter. `send_on_wire(&bytes)` ships the spec's own IP layer and the
        // kernel routes by the packet's headers, so a spec crafting an out-of-scope or
        // denylisted IP could otherwise ride an in-scope `dst` param past the guard.
        // Resolve the real target from the built bytes (as the intercept-forward path
        // does via `ip_target`) and refuse a spec whose destination (or port)
        // contradicts the declared `dst`/`port`, or that carries no decodable IP
        // destination — the latter cannot be proven in scope (deny-by-default).
        let real_target = crate::capture::packet_target(&bytes, &interface, L4Direction::Outbound)
            .ok_or_else(|| {
                anyhow::Error::new(L4GuardError::OutOfL4Scope(
                    "crafted packet has no decodable IP destination; cannot verify scope".into(),
                ))
            })?;
        if real_target.dst != Some(dst) {
            return Err(anyhow::Error::new(L4GuardError::OutOfL4Scope(
                real_target
                    .dst
                    .map_or_else(|| dst.to_string(), |d| d.to_string()),
            )));
        }
        if let Some(p) = dst_port {
            if real_target.dst_port != Some(p) {
                return Err(anyhow::Error::new(L4GuardError::OutOfL4Scope(format!(
                    "{dst} (crafted port {:?} ≠ declared {p})",
                    real_target.dst_port
                ))));
            }
        }

        // (1) Primary gate: the L4 guard (scope + dangerous-destination denylist +
        // rate) mints the injection permit the choke point requires, checked against
        // the packet's *real* target. Checked first so the refusal an operator sees is
        // the specific L4 one (deny-by-default).
        let mut permit = self
            .guard
            .check(L4Action::Inject, &real_target)
            .map_err(anyhow::Error::new)?;
        // (2) Defense in depth: the proxy-wide scope/rate/concurrency guard on the
        // destination host. The permit is held across the batch.
        let _active = host
            .guard()
            .check_active(&dst.to_string())
            .map_err(anyhow::Error::new)?;

        // Record the batch in a `Craft` flow (the injected packets, `injected = true`),
        // so `l4.flow.get` shows the round-trip (AC9). Nothing is created for a send the
        // choke point refuses before the loop.
        let flow_id = self.store.insert(L4Flow {
            id: L4FlowId::new(),
            kind: L4FlowKind::Craft,
            bind: L4Bind {
                interface: interface.clone(),
                filter: None,
                queue: None,
            },
            packets: std::collections::VecDeque::new(),
            metadata: L4Meta::default(),
        });

        // Thread the one permit through the batch: its per-call count + size budget
        // bounds the whole loop. A refusal mid-batch returns with what was sent.
        let mut sent: i64 = 0;
        for _ in 0..count {
            send_on_wire(&mut permit, self.backend.as_ref(), &interface, &bytes)
                .map_err(anyhow::Error::new)?;
            self.store.append_packet(
                flow_id,
                L4Packet {
                    dir: L4Direction::Outbound,
                    timestamp: SystemTime::now(),
                    decoded: PacketSpec::summarize(&bytes),
                    bytes: bytes.clone(),
                    injected: true,
                },
            );
            sent += 1;
        }

        let mut obj = BTreeMap::new();
        obj.insert(
            "flow_id".to_string(),
            Value::Str(super::flow_id_to_string(flow_id)),
        );
        obj.insert("sent".to_string(), Value::Int(sent));
        Ok(Value::Object(obj))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use aitm_core::{
        CommandHost, HttpFlow, HttpRequest, MemFlowStore, ProxyClient, ScopeRateGuard, StdGuard,
        Value,
    };
    use futures::future::BoxFuture;

    use crate::backend::{CaptureSource, L4Error};
    use crate::config::L4Config;
    use crate::flow::InMemoryL4FlowStore;
    use crate::guard::L4GuardError;
    use crate::types::{IpCidr, L4Capability, L4ScopeEntry, L4ScopeId, PortRange, RateCap};

    /// A backend that records injected frames, or (unavailable) fails fail-closed.
    struct MockBackend {
        available: bool,
        sent: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl MockBackend {
        fn available() -> Arc<Self> {
            Arc::new(Self {
                available: true,
                sent: Mutex::new(Vec::new()),
            })
        }

        fn sent(&self) -> Vec<(String, Vec<u8>)> {
            self.sent.lock().unwrap().clone()
        }
    }

    struct EmptySource;
    impl CaptureSource for EmptySource {
        fn next_frame(&mut self) -> Result<Option<Vec<u8>>, L4Error> {
            Ok(None)
        }
    }

    impl CaptureInjectBackend for MockBackend {
        fn open_capture(
            &self,
            _iface: &str,
            _filter: Option<&str>,
            _read_timeout: std::time::Duration,
        ) -> Result<Box<dyn CaptureSource>, L4Error> {
            Ok(Box::new(EmptySource))
        }

        fn inject(&self, iface: &str, bytes: &[u8]) -> Result<(), L4Error> {
            if !self.available {
                return Err(L4Error::Unavailable("no privilege (mock)".into()));
            }
            self.sent
                .lock()
                .unwrap()
                .push((iface.to_string(), bytes.to_vec()));
            Ok(())
        }
    }

    struct StubClient;
    impl ProxyClient for StubClient {
        fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            Box::pin(async { anyhow::bail!("stub client") })
        }
    }

    /// A core `CommandHost` with `127.0.0.1` in the proxy-wide scope, so the
    /// defense-in-depth `check_active` admits the loopback target.
    fn core_guard_scoped() -> StdGuard {
        let g = StdGuard::default();
        g.add_scope(aitm_core::ScopeEntry {
            host: "127.0.0.1".into(),
        });
        g
    }

    fn entry(cidr: (&str, u8), iface: &str, cap: L4Capability, rate: (u32, u32)) -> L4ScopeEntry {
        L4ScopeEntry {
            id: L4ScopeId::new(),
            cidr: IpCidr {
                addr: cidr.0.parse().unwrap(),
                prefix: cidr.1,
            },
            ports: PortRange { lo: 0, hi: 65535 },
            interface: iface.to_string(),
            direction: L4Direction::Outbound,
            capability: cap,
            inject_rate: RateCap {
                pps: rate.0,
                burst: rate.1,
            },
            source: crate::types::L4ScopeSource::Config,
        }
    }

    /// An IPv4/UDP/Raw craft spec `Value` (`Layer` is externally tagged, snake_case).
    fn udp_spec_value(dst: &str, dst_port: i64) -> Value {
        let ipv4 = {
            let mut m = BTreeMap::new();
            m.insert("dst".to_string(), Value::Str(dst.into()));
            let mut l = BTreeMap::new();
            l.insert("ipv4".to_string(), Value::Object(m));
            Value::Object(l)
        };
        let udp = {
            let mut m = BTreeMap::new();
            m.insert("dst_port".to_string(), Value::Int(dst_port));
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

    fn inject_params(spec: Value, dst: &str, iface: &str, port: i64, count: i64) -> Params {
        let mut m = BTreeMap::new();
        m.insert("spec".to_string(), spec);
        m.insert("dst".to_string(), Value::Str(dst.into()));
        m.insert("interface".to_string(), Value::Str(iface.into()));
        m.insert("port".to_string(), Value::Int(port));
        m.insert("count".to_string(), Value::Int(count));
        Params::new(m)
    }

    /// Pinned (plan Task 10): command-level `l4.inject` to an out-of-scope dst is
    /// refused with `OutOfL4Scope` by the L4 guard — before the core guard, and
    /// before anything reaches the wire. Hermetic (no privilege).
    #[test]
    fn inject_out_of_scope_refused() {
        let guard = Arc::new(L4Guard::new(&L4Config::default()));
        guard
            .add_scope(entry(
                ("10.0.0.0", 8),
                "eth0",
                L4Capability::Inject,
                (100, 100),
            ))
            .unwrap();
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let backend = MockBackend::available();
        let cmd = Inject::new(guard, store.clone(), backend.clone());

        let mem = MemFlowStore::new();
        let client = StubClient;
        let core = core_guard_scoped();
        let host = CommandHost::new(&mem, &client, &core, None);

        let err = cmd
            .invoke(
                inject_params(udp_spec_value("8.8.8.8", 443), "8.8.8.8", "eth0", 443, 1),
                &host,
            )
            .unwrap_err();
        let typed = err
            .downcast_ref::<L4GuardError>()
            .unwrap_or_else(|| panic!("want a typed L4GuardError, got {err:?}"));
        assert!(
            matches!(typed, L4GuardError::OutOfL4Scope(_)),
            "want OutOfL4Scope, got {typed:?}"
        );
        assert!(backend.sent().is_empty(), "nothing reached the wire");
        assert!(
            store.list().is_empty(),
            "no flow recorded for a refused inject"
        );
    }

    /// C3 (security): a spec whose crafted IP destination is a denylisted host, sent
    /// with an in-scope `dst` param, is refused — the guard gates the packet's real
    /// destination, not the parameter. Nothing reaches the wire; no flow is recorded.
    #[test]
    fn inject_spec_dst_overrides_param_is_refused() {
        // Scope grants Inject to the loopback host the param names...
        let guard = Arc::new(L4Guard::new(&L4Config::default()));
        guard
            .add_scope(entry(
                ("127.0.0.1", 32),
                "lo0",
                L4Capability::Inject,
                (100, 100),
            ))
            .unwrap();
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let backend = MockBackend::available();
        let cmd = Inject::new(guard, store.clone(), backend.clone());

        let mem = MemFlowStore::new();
        let client = StubClient;
        let core = core_guard_scoped();
        let host = CommandHost::new(&mem, &client, &core, None);

        // ...but the spec crafts a packet to the cloud-metadata denylist address while
        // passing the in-scope `dst = 127.0.0.1` to satisfy the param check.
        let err = cmd
            .invoke(
                inject_params(
                    udp_spec_value("169.254.169.254", 9),
                    "127.0.0.1",
                    "lo0",
                    9,
                    1,
                ),
                &host,
            )
            .unwrap_err();
        let typed = err
            .downcast_ref::<L4GuardError>()
            .unwrap_or_else(|| panic!("want a typed L4GuardError, got {err:?}"));
        assert!(
            matches!(typed, L4GuardError::OutOfL4Scope(_)),
            "a spec dst that contradicts the param must be refused, got {typed:?}"
        );
        assert!(backend.sent().is_empty(), "nothing reached the wire");
        assert!(
            store.list().is_empty(),
            "no flow recorded for a refused inject"
        );
    }

    /// Hermetic happy path: an in-scope loopback inject records a `Craft` flow with
    /// the injected packet (`injected = true`) and reports it reached the wire.
    /// Proves AC9's injected-packet flow via the command, no privilege.
    #[test]
    fn inject_records_injected_flow() {
        let guard = Arc::new(L4Guard::new(&L4Config::default()));
        guard
            .add_scope(entry(
                ("127.0.0.1", 32),
                "lo0",
                L4Capability::Inject,
                (100, 100),
            ))
            .unwrap();
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let backend = MockBackend::available();
        let cmd = Inject::new(guard, store.clone(), backend.clone());

        let mem = MemFlowStore::new();
        let client = StubClient;
        let core = core_guard_scoped();
        let host = CommandHost::new(&mem, &client, &core, None);

        let result = cmd
            .invoke(
                inject_params(udp_spec_value("127.0.0.1", 9), "127.0.0.1", "lo0", 9, 1),
                &host,
            )
            .expect("authorized inject runs");

        let Value::Object(obj) = result else {
            panic!("l4.inject returns an object");
        };
        assert_eq!(obj.get("sent"), Some(&Value::Int(1)));
        let Some(Value::Str(flow_id)) = obj.get("flow_id") else {
            panic!("l4.inject returns a flow id");
        };

        // Exactly one frame reached the (mock) wire, on the scoped interface.
        let sent = backend.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, "lo0");

        // The recorded flow is a Craft flow with one injected packet.
        let id = super::super::flow_id_from_str(flow_id).unwrap();
        let flow = store.get(id).expect("inject flow recorded");
        assert_eq!(flow.kind, L4FlowKind::Craft);
        assert_eq!(flow.packets.len(), 1);
        assert!(
            flow.packets[0].injected,
            "an injected packet is injected=true"
        );
        assert_eq!(flow.packets[0].dir, L4Direction::Outbound);
    }

    /// Panel finding (Important): the rate cap is **per packet**, not per `check`. A
    /// single `l4.inject` with `count = pps + 1` must trip `InjectionRateExceeded` on
    /// the (pps+1)-th packet — the batch loop threads one permit and spends a rate
    /// token for every packet, so `inject_rate.pps` is packets/sec. The first `pps`
    /// packets still reach the wire; the overflow one does not.
    #[test]
    fn inject_batch_trips_rate_cap_per_packet() {
        const PPS: u32 = 2;
        let guard = Arc::new(L4Guard::new(&L4Config::default()));
        guard
            .add_scope(entry(
                ("127.0.0.1", 32),
                "lo0",
                L4Capability::Inject,
                (PPS, PPS),
            ))
            .unwrap();
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let backend = MockBackend::available();
        let cmd = Inject::new(guard, store.clone(), backend.clone());

        let mem = MemFlowStore::new();
        let client = StubClient;
        let core = core_guard_scoped();
        let host = CommandHost::new(&mem, &client, &core, None);

        // count = pps + 1: the (pps+1)-th packet exhausts the per-entry rate bucket.
        let err = cmd
            .invoke(
                inject_params(
                    udp_spec_value("127.0.0.1", 9),
                    "127.0.0.1",
                    "lo0",
                    9,
                    i64::from(PPS) + 1,
                ),
                &host,
            )
            .unwrap_err();
        let typed = err
            .downcast_ref::<L4Error>()
            .unwrap_or_else(|| panic!("want a typed L4Error, got {err:?}"));
        assert!(
            matches!(
                typed,
                L4Error::Guard(L4GuardError::InjectionRateExceeded { .. })
            ),
            "the (pps+1)-th packet must trip InjectionRateExceeded, got {typed:?}"
        );
        // Exactly `pps` packets reached the wire before the cap tripped.
        assert_eq!(
            backend.sent().len(),
            PPS as usize,
            "only pps packets are sent before the per-packet rate cap refuses"
        );
    }
}
