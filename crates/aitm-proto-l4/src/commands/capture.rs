//! `l4.capture.start` / `.stop` / `.status` — scoped background packet capture over
//! the command bus (M5 Task 10).
//!
//! Sensitivity: **guarded (`Capture`)** for `start` (read-only for `.stop`/`.status`,
//! which only address captures a prior guarded `start` already authorized). The
//! gating lives in [`start_capture`](crate::capture::start_capture), which mints a
//! `Capture` [`L4Permit`](crate::guard::L4Permit) **before** any libpcap handle
//! opens (deny-by-default, AC8) and holds it for the capture's lifetime; a
//! scope-derived BPF filter and the per-packet guard then keep out-of-scope traffic
//! from ever being recorded.
//!
//! These commands share one [`CaptureRegistry`](crate::capture::CaptureRegistry):
//! `start` registers the live capture, `stop` ends and removes it, `status` lists the
//! running captures by flow id. There is no destination host here (a capture binds an
//! interface, not a single peer), so the core guard's host-keyed `check_active` does
//! not apply — the L4 `Capture` guard is the gate.

use std::collections::BTreeMap;
use std::sync::Arc;

use aitm_core::{Command, CommandHost, ParamDef, ParamSchema, Params, TypeDesc, Value};

use crate::backend::CaptureInjectBackend;
use crate::capture::{start_capture, CaptureParams, CaptureRegistry};
use crate::flow::L4FlowStore;
use crate::guard::L4Guard;
use crate::types::L4Direction;

/// `l4.capture.start {interface, direction?}` → start a scoped, filtered capture;
/// returns the `Capture` flow id it records into.
pub struct CaptureStart {
    guard: Arc<L4Guard>,
    backend: Arc<dyn CaptureInjectBackend>,
    store: Arc<dyn L4FlowStore>,
    registry: Arc<CaptureRegistry>,
}

impl CaptureStart {
    /// A command over the shared guard, backend, store, and capture registry.
    pub fn new(
        guard: Arc<L4Guard>,
        backend: Arc<dyn CaptureInjectBackend>,
        store: Arc<dyn L4FlowStore>,
        registry: Arc<CaptureRegistry>,
    ) -> Self {
        Self {
            guard,
            backend,
            store,
            registry,
        }
    }
}

impl Command for CaptureStart {
    fn name(&self) -> &str {
        "l4.capture.start"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description:
                "Start a scoped, filtered background capture on an interface; returns the \
                          Capture flow id. Guarded (Capture): deny-by-default, a scope-derived BPF \
                          filter, and a per-packet guard re-check."
                    .into(),
            params: vec![
                ParamDef {
                    name: "interface".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "The interface to sniff (e.g. `lo0`, `eth0`).".into(),
                },
                ParamDef {
                    name: "direction".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "`inbound` (default) or `outbound` — which Capture scope entries \
                                  authorize this bind."
                        .into(),
                },
            ],
            result: TypeDesc::Object(vec![ParamDef {
                name: "flow_id".into(),
                ty: TypeDesc::Str,
                required: true,
                description: "The id of the Capture flow this capture appends to.".into(),
            }]),
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let interface = args.get_str("interface")?.to_string();
        let direction = direction_param(&args)?;
        let id = start_and_register(
            self.guard.clone(),
            self.backend.clone(),
            self.store.clone(),
            &self.registry,
            CaptureParams::new(interface, direction),
        )?;
        let mut obj = BTreeMap::new();
        obj.insert(
            "flow_id".to_string(),
            Value::Str(super::flow_id_to_string(id)),
        );
        Ok(Value::Object(obj))
    }
}

/// `l4.capture.stop {id}` → stop and remove the live capture with that flow id;
/// returns whether one was running.
pub struct CaptureStop {
    registry: Arc<CaptureRegistry>,
}

impl CaptureStop {
    /// A command over the shared capture registry.
    pub fn new(registry: Arc<CaptureRegistry>) -> Self {
        Self { registry }
    }
}

impl Command for CaptureStop {
    fn name(&self) -> &str {
        "l4.capture.stop"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description:
                "Stop and remove a running capture by its flow id; returns whether one was \
                          running."
                    .into(),
            params: vec![ParamDef {
                name: "id".into(),
                ty: TypeDesc::Str,
                required: true,
                description: "The Capture flow id returned by `l4.capture.start`.".into(),
            }],
            result: TypeDesc::Bool,
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let id = super::flow_id_from_str(args.get_str("id")?)?;
        Ok(Value::Bool(self.registry.stop(id)))
    }
}

/// `l4.capture.status` → the flow ids of the currently-running captures.
pub struct CaptureStatus {
    registry: Arc<CaptureRegistry>,
}

impl CaptureStatus {
    /// A command over the shared capture registry.
    pub fn new(registry: Arc<CaptureRegistry>) -> Self {
        Self { registry }
    }
}

impl Command for CaptureStatus {
    fn name(&self) -> &str {
        "l4.capture.status"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "List the flow ids of the currently-running captures (read-only).".into(),
            params: vec![],
            result: TypeDesc::Array(Box::new(TypeDesc::Str)),
        }
    }

    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        Ok(Value::Array(
            self.registry
                .list()
                .into_iter()
                .map(|id| Value::Str(super::flow_id_to_string(id)))
                .collect(),
        ))
    }
}

/// Resolve the optional `direction` param (default `inbound`).
fn direction_param(args: &Params) -> anyhow::Result<L4Direction> {
    match args.get("direction") {
        None => Ok(L4Direction::Inbound),
        Some(Value::Str(s)) => super::parse_direction(s),
        Some(other) => anyhow::bail!("param `direction` must be a string, got {other:?}"),
    }
}

/// Start a scoped capture and register it; returns its flow id. Shared by the
/// `CaptureStart` body and its tests.
fn start_and_register(
    guard: Arc<L4Guard>,
    backend: Arc<dyn CaptureInjectBackend>,
    store: Arc<dyn L4FlowStore>,
    registry: &CaptureRegistry,
    params: CaptureParams,
) -> anyhow::Result<crate::flow::L4FlowId> {
    let handle = start_capture(guard, backend, store, params).map_err(anyhow::Error::new)?;
    Ok(registry.register(handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use crate::backend::{CaptureSource, L4Error};
    use crate::config::L4Config;
    use crate::flow::{InMemoryL4FlowStore, L4FlowKind};
    use crate::guard::L4GuardError;
    use crate::types::{IpCidr, L4Capability, L4ScopeEntry, L4ScopeId, PortRange, RateCap};

    /// A capture backend that opens a source yielding no frames (it idles like a real
    /// read timeout). `available == false` simulates missing privilege (fail-closed).
    struct IdleBackend {
        available: bool,
    }

    impl CaptureInjectBackend for IdleBackend {
        fn open_capture(
            &self,
            _iface: &str,
            _filter: Option<&str>,
            _read_timeout: Duration,
        ) -> Result<Box<dyn CaptureSource>, L4Error> {
            if !self.available {
                return Err(L4Error::Unavailable("no privilege (mock)".into()));
            }
            Ok(Box::new(IdleSource {
                opened: AtomicBool::new(false),
            }))
        }

        fn inject(&self, _iface: &str, _bytes: &[u8]) -> Result<(), L4Error> {
            Ok(())
        }
    }

    struct IdleSource {
        opened: AtomicBool,
    }
    impl CaptureSource for IdleSource {
        fn next_frame(&mut self) -> Result<Option<Vec<u8>>, L4Error> {
            // One quick poll, then idle, so the capture thread is responsive to stop.
            self.opened.store(true, Ordering::Release);
            std::thread::sleep(Duration::from_millis(5));
            Ok(None)
        }
    }

    fn capture_guard(cap: L4Capability, direction: L4Direction) -> Arc<L4Guard> {
        let g = L4Guard::new(&L4Config::default());
        g.add_scope(L4ScopeEntry {
            id: L4ScopeId::new(),
            cidr: IpCidr {
                addr: "127.0.0.1".parse().unwrap(),
                prefix: 32,
            },
            ports: PortRange { lo: 0, hi: 65535 },
            interface: "mock0".to_string(),
            direction,
            capability: cap,
            inject_rate: RateCap { pps: 10, burst: 10 },
            source: crate::types::L4ScopeSource::Config,
        })
        .unwrap();
        Arc::new(g)
    }

    fn start_params() -> Params {
        let mut m = BTreeMap::new();
        m.insert("interface".to_string(), Value::Str("mock0".into()));
        Params::new(m)
    }

    fn host<'a>(
        mem: &'a aitm_core::MemFlowStore,
        client: &'a StubClient,
        guard: &'a aitm_core::StdGuard,
    ) -> CommandHost<'a> {
        CommandHost::new(mem, client, guard, None)
    }

    struct StubClient;
    impl aitm_core::ProxyClient for StubClient {
        fn send(
            &self,
            _req: aitm_core::HttpRequest,
        ) -> futures::future::BoxFuture<'_, anyhow::Result<aitm_core::HttpFlow>> {
            Box::pin(async { anyhow::bail!("stub client") })
        }
    }

    /// Hermetic lifecycle: `start` (default inbound direction) registers a live
    /// capture; `status` lists it; `stop` ends and removes it.
    #[test]
    fn capture_start_status_stop_lifecycle() {
        // The capture entry is inbound (the command default).
        let guard = capture_guard(L4Capability::Capture, L4Direction::Inbound);
        let backend: Arc<dyn CaptureInjectBackend> = Arc::new(IdleBackend { available: true });
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let registry = Arc::new(CaptureRegistry::new());

        let start = CaptureStart::new(guard, backend, store.clone(), registry.clone());
        let status = CaptureStatus::new(registry.clone());
        let stop = CaptureStop::new(registry.clone());

        let mem = aitm_core::MemFlowStore::new();
        let client = StubClient;
        let core = aitm_core::StdGuard::default();
        let h = host(&mem, &client, &core);

        let started = start.invoke(start_params(), &h).expect("capture starts");
        let Value::Object(obj) = started else {
            panic!("start returns an object");
        };
        let Some(Value::Str(flow_id)) = obj.get("flow_id") else {
            panic!("start returns a flow id");
        };

        // The flow exists and is a Capture flow.
        let id = super::super::flow_id_from_str(flow_id).unwrap();
        assert_eq!(
            store.get(id).expect("capture flow present").kind,
            L4FlowKind::Capture
        );

        // status lists exactly this capture.
        let listed = status.invoke(Params::default(), &h).expect("status ok");
        assert_eq!(listed, Value::Array(vec![Value::Str(flow_id.clone())]));

        // stop ends it; status is then empty; a second stop is false.
        let mut sm = BTreeMap::new();
        sm.insert("id".to_string(), Value::Str(flow_id.clone()));
        assert_eq!(
            stop.invoke(Params::new(sm.clone()), &h).expect("stop ok"),
            Value::Bool(true)
        );
        assert_eq!(
            status.invoke(Params::default(), &h).expect("status ok"),
            Value::Array(vec![])
        );
        assert_eq!(
            stop.invoke(Params::new(sm), &h).expect("stop ok"),
            Value::Bool(false)
        );
    }

    /// Deny-by-default (AC1/AC8): `l4.capture.start` with an empty scope is refused
    /// with `OutOfL4Scope` and registers no capture.
    #[test]
    fn capture_start_empty_scope_refused() {
        let guard = Arc::new(L4Guard::new(&L4Config::default()));
        let backend: Arc<dyn CaptureInjectBackend> = Arc::new(IdleBackend { available: true });
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let registry = Arc::new(CaptureRegistry::new());
        let start = CaptureStart::new(guard, backend, store, registry.clone());

        let mem = aitm_core::MemFlowStore::new();
        let client = StubClient;
        let core = aitm_core::StdGuard::default();
        let h = host(&mem, &client, &core);

        let err = start.invoke(start_params(), &h).unwrap_err();
        let typed = err
            .downcast_ref::<L4Error>()
            .unwrap_or_else(|| panic!("want a typed L4Error, got {err:?}"));
        assert!(
            matches!(typed, L4Error::Guard(L4GuardError::OutOfL4Scope(_))),
            "want Guard(OutOfL4Scope), got {typed:?}"
        );
        assert!(
            registry.is_empty(),
            "no capture registered for a refused start"
        );
    }

    /// The Task-10 wire commands are all registered by `wire_commands`.
    #[test]
    fn wire_commands_registered() {
        let guard = Arc::new(L4Guard::new(&L4Config::default()));
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let cmds = super::super::wire_commands(guard, store);
        let names: Vec<&str> = cmds.iter().map(|c| c.name()).collect();
        for want in [
            "l4.capture.start",
            "l4.capture.stop",
            "l4.capture.status",
            "l4.inject",
            "l4.send_recv",
        ] {
            assert!(names.contains(&want), "{want} must be in wire_commands");
        }
    }
}
