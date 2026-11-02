//! Privilege plan P1b.7 (spec §2.1, §2.4, L4PRIV-AC7, AC27): the wire verbs are
//! gated **live** on the shared `PrivilegeState`, so a core started before
//! approval serves capture after it without a rebuild, and the gate forwards the
//! wrapped command's `confirm_prompt` so the operator handshake survives gating.
//!
//! Hermetic: the module is built over a scripted prober (macOS row 5 of the
//! spec §2.2 table, "the handoff app embeds the helper plist") and an injected
//! clock, so the literals below hold on any host and nothing touches `/dev/bpf*`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use aitm_core::{
    CommandHost, Frontend, HttpFlow, HttpRequest, MemFlowStore, Params, ProxyClient, Registry,
    StdGuard, Value,
};
use aitm_proto_l4::config::{L4Config, L4PrivilegeConfig};
use aitm_proto_l4::guard::L4GuardError;
use aitm_proto_l4::privilege::derive::{MacInputs, ProbeInputs};
use aitm_proto_l4::privilege::report::{Platform, RequestProgress};
use aitm_proto_l4::privilege::state::{PrivilegeConfig, Prober, ProcessLifetime, REPROBE_MS};
use aitm_proto_l4::privilege::PrivilegeState;
use aitm_proto_l4::types::{
    IpCidr, L4Capability, L4Direction, L4ScopeEntry, L4ScopeId, L4ScopeSource, PortRange, RateCap,
};
use aitm_proto_l4::{L4Error, L4Module};
use futures::future::BoxFuture;

/// The exact text `L4Gated` refuses with for macOS row 5 (plan p1b "Reason text").
const ROW5_GATED: &str =
    "L4 unavailable: packet capture is not allowed yet (Allow packet capture in the Aitmproxy app)";

// ---- scaffolding --------------------------------------------------------------

struct StubClient;
impl ProxyClient for StubClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

/// A macOS prober whose `/dev/bpf*` open flips when the test says so: row 5
/// (no open, no receipt, the handoff app embeds the helper) until `allow`, row
/// 2 (opens read+write) after.
struct FlipProber {
    bpf_opens: Arc<AtomicBool>,
}

impl Prober for FlipProber {
    fn gather(&self, request: Option<&RequestProgress>) -> ProbeInputs {
        ProbeInputs {
            enabled: true,
            platform: Platform::Macos,
            mac: Some(MacInputs {
                bpf_rw_opens: self.bpf_opens.load(Ordering::SeqCst),
                receipt: None,
                handoff_app_embeds_helper: true,
            }),
            linux: None,
            request: request.cloned(),
            now_ms: 0,
        }
    }
}

/// The scripted world: the flip switch, the clock, and the state built over them.
struct World {
    bpf_opens: Arc<AtomicBool>,
    now: Arc<AtomicU64>,
    state: Arc<PrivilegeState>,
}

impl World {
    fn new() -> Self {
        let bpf_opens = Arc::new(AtomicBool::new(false));
        let now = Arc::new(AtomicU64::new(0));
        let clock_now = Arc::clone(&now);
        let cfg = PrivilegeConfig {
            enabled: true,
            l4: L4PrivilegeConfig::default(),
            lifetime: ProcessLifetime::Serving,
        };
        let state = PrivilegeState::with_prober(
            &cfg,
            Box::new(FlipProber {
                bpf_opens: Arc::clone(&bpf_opens),
            }),
            Arc::new(move || clock_now.load(Ordering::SeqCst)),
        );
        Self {
            bpf_opens,
            now,
            state: Arc::new(state),
        }
    }

    /// The OS grants the privilege and the state's TTL elapses: 1.1 s later.
    fn approve_and_wait(&self) {
        self.bpf_opens.store(true, Ordering::SeqCst);
        self.now.fetch_add(REPROBE_MS + 100, Ordering::SeqCst);
    }
}

/// An enabled config with no `l4.intercept` block and one Inject scope entry for
/// `127.0.0.1` on `lo0`, so the inner `l4.inject` / `l4.send_recv` offer a
/// confirm prompt for an in-scope target. No Capture entry: a capture start that
/// gets past the privilege gate is refused by the guard, never by the wire.
fn cfg() -> L4Config {
    L4Config {
        enabled: true,
        intercept: None,
        scope: vec![L4ScopeEntry {
            id: L4ScopeId::new(),
            cidr: IpCidr {
                addr: "127.0.0.1".parse().expect("literal v4"),
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

fn registry(world: &World) -> Registry {
    let module = L4Module::with_state(&cfg(), Arc::clone(&world.state));
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(module));
    reg
}

struct Parts {
    store: MemFlowStore,
    client: StubClient,
    guard: StdGuard,
}

impl Parts {
    fn new() -> Self {
        Self {
            store: MemFlowStore::new(),
            client: StubClient,
            guard: StdGuard::default(),
        }
    }

    /// An operator host: trusted control, so the agent gate under the privilege
    /// gate lets the call through to the inner command.
    fn operator(&self) -> CommandHost<'_> {
        CommandHost::new(&self.store, &self.client, &self.guard, None)
            .with_frontend(Frontend::Operator)
    }
}

fn one(key: &str, value: Value) -> Params {
    let mut m = BTreeMap::new();
    m.insert(key.to_string(), value);
    Params::new(m)
}

fn start_params() -> Params {
    one("interface", Value::Str("lo0".into()))
}

/// An IPv4/UDP/Raw craft spec in the `Value` shape `l4.inject` accepts.
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

/// `l4.inject` / `l4.send_recv` params for the in-scope target `127.0.0.1:9` on `lo0`.
fn inject_params() -> Params {
    let mut m = BTreeMap::new();
    m.insert("spec".to_string(), craft_spec());
    m.insert("dst".to_string(), Value::Str("127.0.0.1".into()));
    m.insert("interface".to_string(), Value::Str("lo0".into()));
    m.insert("port".to_string(), Value::Int(9));
    Params::new(m)
}

fn invoke(reg: &Registry, name: &str, params: Params, host: &CommandHost) -> anyhow::Result<Value> {
    reg.command(name)
        .unwrap_or_else(|| panic!("{name} registered"))
        .invoke(params, host)
}

// ---- tests --------------------------------------------------------------------

/// L4PRIV-AC7 (unit half) + AC27: one module, one state. Before approval the
/// gated verbs refuse with the row-5 text; after the OS flips and the TTL passes,
/// the same module (no rebuild) delegates to the inner command; and the operator
/// confirm prompts are offered through the gate both before and after.
#[test]
fn gated_verbs_flip_live_and_stay_confirmable() {
    let world = World::new();
    let reg = registry(&world);
    let parts = Parts::new();
    let host = parts.operator();

    // 1. Before the flip: the exact gated text, for capture and inject alike.
    let err = invoke(&reg, "l4.capture.start", start_params(), &host)
        .expect_err("capture.start must refuse before approval");
    assert_eq!(err.to_string(), ROW5_GATED);
    let typed = err
        .downcast_ref::<L4Error>()
        .unwrap_or_else(|| panic!("want a typed L4Error, got {err:?}"));
    assert!(matches!(typed, L4Error::Unavailable(_)), "got {typed:?}");

    let err = invoke(&reg, "l4.inject", inject_params(), &host)
        .expect_err("inject must refuse before approval");
    assert_eq!(err.to_string(), ROW5_GATED);

    // 3 (before). The confirm prompts come through the gate: the inner
    // `l4.inject` / `l4.send_recv` offer one for this in-scope target, and so
    // must the gated command (AC27). The old `L4Gated` answered `None` here.
    for name in ["l4.inject", "l4.send_recv"] {
        let cmd = reg
            .command(name)
            .unwrap_or_else(|| panic!("{name} registered"));
        assert!(
            cmd.confirm_prompt(&inject_params()).is_some(),
            "{name}: confirm_prompt must be forwarded while gated"
        );
        assert_eq!(
            cmd.sensitivity(),
            aitm_core::Sensitivity::Sensitive,
            "{name}"
        );
    }
    // The `tools/list` probe (`aitm-mcp` schema.rs: `confirm_prompt(&Params::default())`)
    // must read the same through the gate as the inner command answers; it is
    // recorded here so the flip below can show the gate does not change it.
    let confirmable_before: Vec<bool> = [
        "l4.inject",
        "l4.send_recv",
        "l4.intercept.forward",
        "l4.intercept.drop",
    ]
    .iter()
    .map(|name| {
        reg.command(name)
            .unwrap_or_else(|| panic!("{name} registered"))
            .confirm_prompt(&Params::default())
            .is_some()
    })
    .collect();

    // Inside the TTL nothing is re-probed: the OS flip alone changes nothing yet.
    world.bpf_opens.store(true, Ordering::SeqCst);
    world.now.store(500, Ordering::SeqCst);
    let err = invoke(&reg, "l4.capture.start", start_params(), &host)
        .expect_err("still gated inside the TTL");
    assert_eq!(err.to_string(), ROW5_GATED);

    // 2. After the flip and 1.1 s: the SAME registry reaches the inner command.
    // The module hands `wire_commands` the state's routed libpcap backend (P1b.8),
    // so the proof that the inner `l4.capture.start` ran is its guard's refusal:
    // no Capture scope entry exists, and only the inner command consults the
    // guard. It is not an `L4 unavailable:` error and nothing touched the wire.
    world.approve_and_wait();
    let err = invoke(&reg, "l4.capture.start", start_params(), &host)
        .expect_err("no Capture scope: the inner command's guard refuses");
    assert!(
        !err.to_string().starts_with("L4 unavailable: "),
        "the privilege gate must have let the call through, got {err}"
    );
    let typed = err
        .downcast_ref::<L4Error>()
        .unwrap_or_else(|| panic!("want a typed L4Error from the inner command, got {err:?}"));
    assert!(
        matches!(typed, L4Error::Guard(L4GuardError::OutOfL4Scope(_))),
        "the inner command's deny-by-default guard must answer, got {typed:?}"
    );

    // 3 (after). The prompts are still offered, and the `tools/list` probe reads
    // exactly as it did before the flip.
    for name in ["l4.inject", "l4.send_recv"] {
        let cmd = reg
            .command(name)
            .unwrap_or_else(|| panic!("{name} registered"));
        assert!(
            cmd.confirm_prompt(&inject_params()).is_some(),
            "{name}: confirm_prompt must be forwarded once available"
        );
    }
    let confirmable_after: Vec<bool> = [
        "l4.inject",
        "l4.send_recv",
        "l4.intercept.forward",
        "l4.intercept.drop",
    ]
    .iter()
    .map(|name| {
        reg.command(name)
            .unwrap_or_else(|| panic!("{name} registered"))
            .confirm_prompt(&Params::default())
            .is_some()
    })
    .collect();
    assert_eq!(
        confirmable_before, confirmable_after,
        "the gate must not change what tools/list reports as confirmable"
    );
}

/// L4PAR-AC3 kept: `l4.capture.status` `reason` is exactly the text the gated
/// `l4.capture.start` returns after `L4 unavailable: `, and the same for the
/// in-path pair, because both read the one `PrivilegeState`.
#[test]
fn status_reason_equals_gated_text() {
    let world = World::new();
    let reg = registry(&world);
    let parts = Parts::new();
    let host = parts.operator();

    let reason_of = |name: &str| -> String {
        let status = invoke(&reg, name, Params::default(), &host)
            .unwrap_or_else(|e| panic!("{name} must answer while gated, got {e:?}"));
        let Value::Object(fields) = status else {
            panic!("{name} must answer an object, got {status:?}");
        };
        assert_eq!(fields.get("available"), Some(&Value::Bool(false)), "{name}");
        match fields.get("reason") {
            Some(Value::Str(reason)) => reason.clone(),
            other => panic!("{name} must carry a string reason, got {other:?}"),
        }
    };

    let start_err = invoke(&reg, "l4.capture.start", start_params(), &host)
        .expect_err("gated")
        .to_string();
    let gated_text = start_err
        .strip_prefix("L4 unavailable: ")
        .unwrap_or_else(|| panic!("want the `L4 unavailable: ` prefix, got {start_err}"));
    assert_eq!(reason_of("l4.capture.status"), gated_text);
    assert_eq!(
        gated_text,
        "packet capture is not allowed yet (Allow packet capture in the Aitmproxy app)"
    );

    let start_err = invoke(&reg, "l4.intercept.start", start_params(), &host)
        .expect_err("gated")
        .to_string();
    let gated_text = start_err
        .strip_prefix("L4 unavailable: ")
        .unwrap_or_else(|| panic!("want the `L4 unavailable: ` prefix, got {start_err}"));
    assert_eq!(reason_of("l4.intercept.status"), gated_text);
    assert_eq!(gated_text, "in-path interception is Linux only");
}
