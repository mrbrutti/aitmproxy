//! One routed capture/inject backend over the shared [`PrivilegeState`]
//! (privilege plan P1b.8, spec §2.1).
//!
//! Every production caller that used to build its own
//! [`PcapBackend`](super::pcap::PcapBackend) takes `state.backend()` instead:
//! a [`RoutedBackend`] that asks the state, **on every call**, how packet capture
//! is available right now and delegates accordingly:
//!
//! - `Available { via: Process }` → the in-process libpcap backend;
//! - `Available { via: Helper }` → the helper session's backend, once P1b.13 sets
//!   it on the state ([`PrivilegeState::set_helper_backend`]); until then a fixed
//!   [`L4Error::Unavailable`] ([`HELPER_NOT_WIRED`]);
//! - anything else → [`L4Error::Unavailable`] carrying the same text the gated
//!   verbs and the status verbs report
//!   ([`gated_reason`](crate::privilege::availability::gated_reason)).
//!
//! **(Architect's call:** one routed backend rather than a swap, so a Linux helper
//! session that starts after the commands were built is picked up.) The router
//! holds a strong `Arc<PrivilegeState>`: the state never holds a router (only an
//! optional helper backend), so there is no cycle, and the router lives exactly
//! as long as the commands and scripting engine that own it.
//!
//! Fail-closed: the routing decision precedes any libpcap or helper I/O, so a
//! gated core never opens a device or writes a frame.

use std::sync::Arc;
use std::time::Duration;

use super::pcap::PcapBackend;
use super::{CaptureInjectBackend, CaptureSource, L4Error};
use crate::privilege::availability::gated_reason;
use crate::privilege::derive::text::NO_BACKEND;
use crate::privilege::report::{Capability, Via};
use crate::privilege::PrivilegeState;

/// The refusal while capture is available only through the helper but no helper
/// session backend has been set on the state (P1b.13 wires it).
pub const HELPER_NOT_WIRED: &str = "packet-capture helper session is not wired yet";

/// The capture/inject backend every production caller holds: routes each call on
/// the state's current [`PrivilegeReport`](crate::privilege::report::PrivilegeReport).
pub struct RoutedBackend {
    state: Arc<PrivilegeState>,
    /// The in-process path, taken when the capability is `Available { via: Process }`.
    process: Arc<dyn CaptureInjectBackend>,
}

impl std::fmt::Debug for RoutedBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoutedBackend")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl RoutedBackend {
    /// The production router: libpcap in process when the state says `Process`.
    #[must_use]
    pub fn new(state: Arc<PrivilegeState>) -> Self {
        Self::with_process_backend(state, Arc::new(PcapBackend::new()))
    }

    /// A router whose in-process path is `process`; tests inject a mock here.
    #[must_use]
    pub fn with_process_backend(
        state: Arc<PrivilegeState>,
        process: Arc<dyn CaptureInjectBackend>,
    ) -> Self {
        Self { state, process }
    }

    /// Pick the backend for one capability reading, fail-closed.
    fn route(&self, capability: &Capability) -> Result<Arc<dyn CaptureInjectBackend>, L4Error> {
        match capability {
            Capability::Available { via: Via::Process } => Ok(self.process.clone()),
            Capability::Available { via: Via::Helper } => self
                .state
                .helper_backend()
                .ok_or_else(|| L4Error::Unavailable(HELPER_NOT_WIRED.to_string())),
            gated => Err(L4Error::Unavailable(
                // `gated_reason` is `None` only for `Available`, matched above; the
                // fallback keeps this total without a panic.
                gated_reason(gated).unwrap_or_else(|| NO_BACKEND.to_string()),
            )),
        }
    }
}

impl CaptureInjectBackend for RoutedBackend {
    fn open_capture(
        &self,
        iface: &str,
        filter: Option<&str>,
        read_timeout: Duration,
    ) -> Result<Box<dyn CaptureSource>, L4Error> {
        let report = self.state.report();
        self.route(&report.capture)?
            .open_capture(iface, filter, read_timeout)
    }

    fn inject(&self, iface: &str, bytes: &[u8]) -> Result<(), L4Error> {
        let report = self.state.report();
        self.route(&report.inject)?.inject(iface, bytes)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use aitm_core::{
        CommandHost, HttpFlow, HttpRequest, MemFlowStore, Params, ProxyClient, StdGuard, Value,
    };
    use futures::future::BoxFuture;

    use super::*;
    use crate::backend::{CaptureInjectBackend, CaptureSource, L4Error};
    use crate::config::{L4Config, L4PrivilegeConfig};
    use crate::flow::{InMemoryL4FlowStore, L4FlowStore};
    use crate::guard::L4Guard;
    use crate::module::{AvailabilitySource, L4Availability};
    use crate::privilege::derive::{LinuxInputs, MacInputs, ProbeInputs};
    use crate::privilege::report::{Platform, RequestProgress};
    use crate::privilege::state::{PrivilegeConfig, Prober, ProcessLifetime};
    use crate::privilege::PrivilegeState;
    use crate::types::{
        IpCidr, L4Capability, L4Direction, L4ScopeEntry, L4ScopeId, L4ScopeSource, PortRange,
        RateCap,
    };

    /// macOS row 6 of the spec §2.2 table: nothing opens, no receipt, no handoff
    /// app. The exact gated text (plan p1b "Reason text").
    const ROW6_REASON: &str = "packet capture is not allowed yet (Install the Aitmproxy app (DMG \
                               or Homebrew cask); it asks macOS for packet-capture permission)";

    // ---- scaffolding ----------------------------------------------------------

    /// A prober that always answers the same inputs.
    struct Fixed(ProbeInputs);

    impl Prober for Fixed {
        fn gather(&self, request: Option<&RequestProgress>) -> ProbeInputs {
            let mut inputs = self.0.clone();
            inputs.request = request.cloned();
            inputs
        }
    }

    fn mac_inputs(bpf_rw_opens: bool) -> ProbeInputs {
        ProbeInputs {
            enabled: true,
            platform: Platform::Macos,
            mac: Some(MacInputs {
                bpf_rw_opens,
                receipt: None,
                handoff_app_embeds_helper: false,
            }),
            linux: None,
            request: None,
            now_ms: 0,
        }
    }

    /// Linux with a connected helper session and no process capability: the
    /// table's `Available { via: Helper }` row.
    fn linux_helper_session_inputs() -> ProbeInputs {
        ProbeInputs {
            enabled: true,
            platform: Platform::Linux,
            mac: None,
            linux: Some(LinuxInputs {
                cap_net_raw: false,
                cap_net_admin: false,
                session_connected: true,
                helper: None,
                policy_file_present: false,
                pkexec_present: false,
                prompt_possible: false,
            }),
            request: None,
            now_ms: 0,
        }
    }

    fn state_over(inputs: ProbeInputs) -> Arc<PrivilegeState> {
        let cfg = PrivilegeConfig {
            enabled: true,
            l4: L4PrivilegeConfig::default(),
            lifetime: ProcessLifetime::Serving,
        };
        Arc::new(PrivilegeState::with_prober(
            &cfg,
            Box::new(Fixed(inputs)),
            Arc::new(|| 0),
        ))
    }

    /// A backend that counts and records every call it receives.
    struct MockBackend {
        opens: AtomicU64,
        sent: Mutex<Vec<(String, Vec<u8>)>>,
        opened: Mutex<Vec<String>>,
    }

    impl MockBackend {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                opens: AtomicU64::new(0),
                sent: Mutex::new(Vec::new()),
                opened: Mutex::new(Vec::new()),
            })
        }

        fn calls(&self) -> u64 {
            self.opens.load(Ordering::SeqCst) + self.sent.lock().unwrap().len() as u64
        }

        fn sent(&self) -> Vec<(String, Vec<u8>)> {
            self.sent.lock().unwrap().clone()
        }

        fn opened(&self) -> Vec<String> {
            self.opened.lock().unwrap().clone()
        }
    }

    struct IdleSource;
    impl CaptureSource for IdleSource {
        fn next_frame(&mut self) -> Result<Option<Vec<u8>>, L4Error> {
            std::thread::sleep(Duration::from_millis(5));
            Ok(None)
        }
    }

    impl CaptureInjectBackend for MockBackend {
        fn open_capture(
            &self,
            iface: &str,
            _filter: Option<&str>,
            _read_timeout: Duration,
        ) -> Result<Box<dyn CaptureSource>, L4Error> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            self.opened.lock().unwrap().push(iface.to_string());
            Ok(Box::new(IdleSource))
        }

        fn inject(&self, iface: &str, bytes: &[u8]) -> Result<(), L4Error> {
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

    /// A guard with one inbound Capture entry on `mock0`, so `l4.capture.start`
    /// gets past the scope check and reaches the backend.
    fn capture_guard() -> Arc<L4Guard> {
        let g = L4Guard::new(&L4Config::default());
        g.add_scope(L4ScopeEntry {
            id: L4ScopeId::new(),
            cidr: IpCidr {
                addr: "127.0.0.1".parse().unwrap(),
                prefix: 32,
            },
            ports: PortRange { lo: 0, hi: 65535 },
            interface: "mock0".to_string(),
            direction: L4Direction::Inbound,
            capability: L4Capability::Capture,
            inject_rate: RateCap { pps: 10, burst: 10 },
            source: L4ScopeSource::Config,
        })
        .unwrap();
        Arc::new(g)
    }

    fn always_available() -> AvailabilitySource {
        Arc::new(|| L4Availability::Available)
    }

    fn one(key: &str, value: Value) -> Params {
        let mut m = BTreeMap::new();
        m.insert(key.to_string(), value);
        Params::new(m)
    }

    /// The wire commands built over `router`, by name.
    fn wire_over(
        router: Arc<dyn CaptureInjectBackend>,
    ) -> BTreeMap<String, Arc<dyn aitm_core::Command>> {
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let (gated, _status) = crate::commands::wire_commands(
            capture_guard(),
            store,
            always_available(),
            router,
            Arc::new(|| None),
        );
        gated
            .into_iter()
            .map(|cmd| (cmd.name().to_string(), cmd))
            .collect()
    }

    fn unavailable_text(err: &L4Error) -> &str {
        match err {
            L4Error::Unavailable(text) => text,
            other => panic!("want L4Error::Unavailable, got {other:?}"),
        }
    }

    // ---- tests --------------------------------------------------------------

    /// Plan P1b.8: over a state whose prober says `Available { via: Process }`
    /// (macOS row 2), a capture started through `wire_commands` and an inject
    /// through the router both reach the injected process backend.
    #[test]
    fn routes_to_process_backend_when_available_via_process() {
        let state = state_over(mac_inputs(true));
        let mock = MockBackend::new();
        let router: Arc<dyn CaptureInjectBackend> = Arc::new(RoutedBackend::with_process_backend(
            Arc::clone(&state),
            mock.clone(),
        ));

        // Through `wire_commands`: the backend parameter is what `l4.capture.start`
        // opens on.
        let cmds = wire_over(router.clone());
        let mem = MemFlowStore::new();
        let client = StubClient;
        let core = StdGuard::default();
        let host = CommandHost::new(&mem, &client, &core, None);

        let started = cmds["l4.capture.start"]
            .invoke(one("interface", Value::Str("mock0".into())), &host)
            .expect("capture starts over the routed backend");
        let Value::Object(obj) = started else {
            panic!("start returns an object");
        };
        let Some(Value::Str(flow_id)) = obj.get("flow_id") else {
            panic!("start returns a flow id");
        };
        assert_eq!(mock.opened(), vec!["mock0".to_string()]);
        assert_eq!(
            cmds["l4.capture.stop"]
                .invoke(one("id", Value::Str(flow_id.clone())), &host)
                .expect("stop ok"),
            Value::Bool(true)
        );

        // Through the router directly: inject reaches the same process backend.
        router
            .inject("mock0", &[0xde, 0xad, 0xbe, 0xef])
            .expect("inject routes to the process backend");
        assert_eq!(
            mock.sent(),
            vec![("mock0".to_string(), vec![0xde, 0xad, 0xbe, 0xef])]
        );
        assert_eq!(mock.calls(), 2, "one open, one inject");
    }

    /// Plan P1b.8: a not-available state (macOS row 6) refuses both primitives
    /// with the gated text, and the process backend is never called, whether the
    /// call comes through the router or through `wire_commands`' `l4.capture.start`.
    /// `PrivilegeState::backend()` routes the same way before any libpcap call.
    #[test]
    fn unavailable_state_refuses_without_touching_a_backend() {
        let state = state_over(mac_inputs(false));
        let mock = MockBackend::new();
        let router: Arc<dyn CaptureInjectBackend> = Arc::new(RoutedBackend::with_process_backend(
            Arc::clone(&state),
            mock.clone(),
        ));

        let err = router.inject("mock0", &[1, 2, 3]).unwrap_err();
        assert_eq!(unavailable_text(&err), ROW6_REASON);
        assert!(unavailable_text(&err).starts_with("packet capture is not allowed yet ("));

        let err = router
            .open_capture("mock0", None, Duration::from_millis(10))
            .err()
            .expect("open_capture refuses");
        assert_eq!(unavailable_text(&err), ROW6_REASON);

        // Through the wire command, with no `L4Gated` wrapper in front: the router
        // itself is the fail-closed layer.
        let cmds = wire_over(router);
        let mem = MemFlowStore::new();
        let client = StubClient;
        let core = StdGuard::default();
        let host = CommandHost::new(&mem, &client, &core, None);
        let err = cmds["l4.capture.start"]
            .invoke(one("interface", Value::Str("mock0".into())), &host)
            .unwrap_err();
        assert_eq!(err.to_string(), format!("L4 unavailable: {ROW6_REASON}"));
        let typed = err
            .downcast_ref::<L4Error>()
            .unwrap_or_else(|| panic!("want a typed L4Error, got {err:?}"));
        assert_eq!(unavailable_text(typed), ROW6_REASON);

        // The production router over the default (libpcap) process backend routes
        // before it would touch pcap.
        let err = state.backend().inject("mock0", &[1, 2, 3]).unwrap_err();
        assert_eq!(unavailable_text(&err), ROW6_REASON);

        assert_eq!(mock.calls(), 0, "the backend is never called while gated");
    }

    /// The P1b.13 seam: `Available { via: Helper }` goes to the helper backend set
    /// on the state. Until one is set it refuses with a fixed text, and the
    /// process backend is never consulted either way.
    #[test]
    fn helper_route_uses_the_state_slot() {
        let state = state_over(linux_helper_session_inputs());
        let process = MockBackend::new();
        let router: Arc<dyn CaptureInjectBackend> = Arc::new(RoutedBackend::with_process_backend(
            Arc::clone(&state),
            process.clone(),
        ));

        let err = router.inject("lo", &[9]).unwrap_err();
        assert_eq!(unavailable_text(&err), HELPER_NOT_WIRED);
        assert_eq!(
            HELPER_NOT_WIRED,
            "packet-capture helper session is not wired yet"
        );
        let err = router
            .open_capture("lo", None, Duration::from_millis(10))
            .err()
            .expect("open_capture refuses");
        assert_eq!(unavailable_text(&err), HELPER_NOT_WIRED);

        let helper = MockBackend::new();
        state.set_helper_backend(Some(helper.clone()));
        router
            .inject("lo", &[9])
            .expect("inject goes to the helper");
        let mut source = router
            .open_capture("lo", Some("udp"), Duration::from_millis(10))
            .expect("capture opens on the helper");
        assert_eq!(source.next_frame().unwrap(), None);
        assert_eq!(helper.sent(), vec![("lo".to_string(), vec![9])]);
        assert_eq!(helper.opened(), vec!["lo".to_string()]);

        // Clearing the slot (a session that ended) closes the route again.
        state.set_helper_backend(None);
        let err = router.inject("lo", &[9]).unwrap_err();
        assert_eq!(unavailable_text(&err), HELPER_NOT_WIRED);

        assert_eq!(process.calls(), 0, "the process backend is never consulted");
        assert_eq!(helper.calls(), 2);
    }
}
