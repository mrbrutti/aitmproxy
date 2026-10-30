//! Task 6 — L4 as the first consumer of the `ProtocolLanguage` seam.
//!
//! - **AC4** — `l4.*` verbs are reachable in a Rhai script via the seam, each
//!   gated by the shared `L4Guard` + `allow_agent_*` gates (the command path's
//!   two dimensions): a Sensitive verb (`l4.send_recv`) is refused when its agent
//!   gate is closed and runs when open; a Read verb (`l4.interfaces`) is ungated.
//! - **AC5** — the normative `l4:` PoC step round-trips (YAML ↔ model), runs
//!   `send_recv` over a `MockBackend` SYN-ACK reply, binds the `packet` extractor
//!   (`field: tcp.flags`), and a `dsl` success passes against an in-scope loopback
//!   target — and is refused when the target is out of scope.
//! - **AC8** — the catalog host-fn names, the `l4:` step `op` verbs, and the
//!   `aitm-plugin-rhai`-registered `l4.*` host fns are the one set, each a real
//!   `l4.*` command on the bus.
//!
//! All hermetic: a `MockBackend` records injected frames and replays scripted
//! replies, so nothing binds a socket or needs raw privilege (sandbox-safe).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aitm_core::Value;
use aitm_plugin::language::{PocStepInputs, ProtocolLanguage};
use aitm_plugin_rhai::{
    build_engine_with_languages, production_languages, registered_host_fns, RhaiLimits,
};
use aitm_proto_l4::backend::{CaptureInjectBackend, CaptureSource, L4Error};
use aitm_proto_l4::config::L4Config;
use aitm_proto_l4::craft::{Ipv4Spec, Layer, PacketSpec, TcpSpec};
use aitm_proto_l4::flow::InMemoryL4FlowStore;
use aitm_proto_l4::guard::L4Guard;
use aitm_proto_l4::language::L4Language;
use aitm_proto_l4::module::{L4Module, L4Privilege};
use aitm_proto_l4::types::{
    IpCidr, L4Capability, L4Direction, L4ScopeEntry, L4ScopeId, L4ScopeSource, PortRange, RateCap,
};

const IFACE: &str = "lo";

// --- a hermetic capture/inject backend (no socket, no privilege) ------------

struct MockBackend {
    available: bool,
    replies: Mutex<Option<Vec<Vec<u8>>>>,
    injected: Mutex<Vec<Vec<u8>>>,
}

impl MockBackend {
    fn with_replies(replies: Vec<Vec<u8>>) -> Arc<Self> {
        Arc::new(Self {
            available: true,
            replies: Mutex::new(Some(replies)),
            injected: Mutex::new(Vec::new()),
        })
    }

    fn injected(&self) -> Vec<Vec<u8>> {
        self.injected.lock().unwrap().clone()
    }
}

impl CaptureInjectBackend for MockBackend {
    fn open_capture(
        &self,
        _iface: &str,
        _filter: Option<&str>,
        _read_timeout: Duration,
    ) -> Result<Box<dyn CaptureSource>, L4Error> {
        if !self.available {
            return Err(L4Error::Unavailable("no privilege (mock)".into()));
        }
        let replies = self.replies.lock().unwrap().take().unwrap_or_default();
        Ok(Box::new(ReplySource {
            frames: replies.into(),
        }))
    }

    fn inject(&self, _iface: &str, bytes: &[u8]) -> Result<(), L4Error> {
        self.injected.lock().unwrap().push(bytes.to_vec());
        Ok(())
    }
}

struct ReplySource {
    frames: std::collections::VecDeque<Vec<u8>>,
}

impl CaptureSource for ReplySource {
    fn next_frame(&mut self) -> Result<Option<Vec<u8>>, L4Error> {
        match self.frames.pop_front() {
            Some(f) => Ok(Some(f)),
            None => {
                std::thread::sleep(Duration::from_millis(2));
                Ok(None)
            }
        }
    }
}

// --- shared fixtures --------------------------------------------------------

fn entry(dir: L4Direction, cap: L4Capability) -> L4ScopeEntry {
    L4ScopeEntry {
        id: L4ScopeId::new(),
        cidr: IpCidr {
            addr: "127.0.0.1".parse().unwrap(),
            prefix: 32,
        },
        ports: PortRange { lo: 0, hi: 65535 },
        interface: IFACE.to_string(),
        direction: dir,
        capability: cap,
        inject_rate: RateCap {
            pps: 100,
            burst: 100,
        },
        // Config provenance lifts the loopback dangerous-destination denylist for
        // this explicit /32 (the only way an authorized loopback test is scoped).
        source: L4ScopeSource::Config,
    }
}

/// A guard scoped for a loopback send_recv (inject out + capture in on `lo`),
/// with the agent inject gate set as requested.
fn loopback_guard(allow_agent_inject: bool) -> Arc<L4Guard> {
    let cfg = L4Config {
        scope: vec![
            entry(L4Direction::Outbound, L4Capability::Inject),
            entry(L4Direction::Inbound, L4Capability::Capture),
        ],
        allow_agent_inject,
        ..L4Config::default()
    };
    Arc::new(L4Guard::new(&cfg))
}

/// A SYN-ACK reply from 127.0.0.1:80 — the reversed five-tuple of a SYN sent to
/// 127.0.0.1:80 whose source port is 0 (the TcpSpec default the `l4:` body uses).
fn synack_reply() -> Vec<u8> {
    PacketSpec {
        layers: vec![
            Layer::Ipv4(Ipv4Spec {
                src: Some("127.0.0.1".parse().unwrap()),
                dst: Some("127.0.0.1".parse().unwrap()),
                ..Ipv4Spec::default()
            }),
            Layer::Tcp(TcpSpec {
                src_port: Some(80),
                dst_port: Some(0),
                flags: Some(0x12), // SYN|ACK
                ..TcpSpec::default()
            }),
        ],
    }
    .build()
    .expect("synack builds")
}

// ===========================================================================
// AC4 — l4.* reachable in a Rhai script, each gated
// ===========================================================================

/// A Rhai UDP `send_recv` stimulus to 127.0.0.1:9 (the serde `PacketSpec` form,
/// mirroring the `l4.craft`/`l4.send_recv` command arguments).
const SEND_RECV_SCRIPT: &str = r#"
    let spec = #{ layers: [ #{ ipv4: #{ dst: "127.0.0.1" } }, #{ udp: #{ dst_port: 9 } } ] };
    l4.send_recv(spec, "127.0.0.1", "lo", 9, 50)
"#;

#[test]
fn ac4_sensitive_verb_refused_when_agent_gate_closed() {
    // Agent-sourced engine, inject gate CLOSED (deny-by-default).
    let lang = L4Language::new(
        loopback_guard(false),
        MockBackend::with_replies(vec![]),
        Arc::new(InMemoryL4FlowStore::new()),
        true,
    );
    let engine =
        build_engine_with_languages(&RhaiLimits::default(), Duration::from_secs(5), &[&lang])
            .expect("engine builds with l4 installed");

    let err = engine
        .eval::<rhai::Dynamic>(SEND_RECV_SCRIPT)
        .expect_err("a closed agent gate refuses l4.send_recv");
    let msg = err.to_string();
    assert!(
        msg.contains("disabled") && msg.contains("inject"),
        "the refusal must name the disabled inject capability, got: {msg}"
    );
}

#[test]
fn ac4_sensitive_verb_runs_when_agent_gate_open() {
    // Agent-sourced engine, inject gate OPEN; MockBackend has no reply, so the
    // call SUCCEEDS with a no_response outcome (the gate + scope admitted it).
    let backend = MockBackend::with_replies(vec![]);
    let lang = L4Language::new(
        loopback_guard(true),
        backend.clone(),
        Arc::new(InMemoryL4FlowStore::new()),
        true,
    );
    let engine =
        build_engine_with_languages(&RhaiLimits::default(), Duration::from_secs(5), &[&lang])
            .expect("engine builds");

    let out = engine
        .eval::<rhai::Dynamic>(SEND_RECV_SCRIPT)
        .expect("an open agent gate admits l4.send_recv");
    let map = out
        .try_cast::<rhai::Map>()
        .expect("send_recv returns a map");
    let outcome = map.get("outcome").expect("outcome field").clone();
    let outcome = outcome.try_cast::<rhai::Map>().expect("outcome is a map");
    assert_eq!(
        outcome.get("kind").unwrap().clone().into_string().unwrap(),
        "no_response"
    );
    // The stimulus actually reached the (mock) wire exactly once.
    assert_eq!(backend.injected().len(), 1);
}

#[test]
fn ac4_read_verb_is_ungated() {
    // Even with every agent gate closed, a Read verb (`l4.interfaces`) runs: it is
    // not gated by any capability flag.
    let lang = L4Language::new(
        loopback_guard(false),
        MockBackend::with_replies(vec![]),
        Arc::new(InMemoryL4FlowStore::new()),
        true,
    );
    let engine =
        build_engine_with_languages(&RhaiLimits::default(), Duration::from_secs(5), &[&lang])
            .expect("engine builds");
    let out = engine
        .eval::<rhai::Dynamic>("l4.interfaces()")
        .expect("l4.interfaces is ungated");
    assert!(out.is_array(), "l4.interfaces returns an array");
}

#[test]
fn ac4_operator_engine_bypasses_the_agent_gate() {
    // An operator-authored engine (agent_sourced = false) is the control: the
    // closed agent gate does not apply, so the in-scope send_recv runs.
    let lang = L4Language::new(
        loopback_guard(false),
        MockBackend::with_replies(vec![]),
        Arc::new(InMemoryL4FlowStore::new()),
        false,
    );
    let engine =
        build_engine_with_languages(&RhaiLimits::default(), Duration::from_secs(5), &[&lang])
            .expect("engine builds");
    let _ = engine
        .eval::<rhai::Dynamic>(SEND_RECV_SCRIPT)
        .expect("operator engine bypasses the agent gate");
}

#[test]
fn ac4_out_of_scope_send_recv_refusal_surfaces_to_the_script() {
    // Agent-sourced engine, inject gate OPEN, so the refusal is NOT the agent gate
    // — it is the shared L4Guard's deny-by-default scope check: a Rhai script that
    // calls l4.send_recv to a host no scope entry covers sees the "out of L4 scope"
    // refusal surface as an eval error (AC4's scope refusal on the script face).
    let backend = MockBackend::with_replies(vec![]);
    let lang = L4Language::new(
        loopback_guard(true),
        backend.clone(),
        Arc::new(InMemoryL4FlowStore::new()),
        true,
    );
    let engine =
        build_engine_with_languages(&RhaiLimits::default(), Duration::from_secs(5), &[&lang])
            .expect("engine builds");
    let script = r#"
        let spec = #{ layers: [ #{ ipv4: #{ dst: "10.9.9.9" } }, #{ udp: #{ dst_port: 9 } } ] };
        l4.send_recv(spec, "10.9.9.9", "lo", 9, 50)
    "#;
    let err = engine
        .eval::<rhai::Dynamic>(script)
        .expect_err("an out-of-scope send_recv is refused");
    assert!(
        err.to_string().contains("out of L4 scope"),
        "the deny-by-default scope refusal must surface to the script, got: {err}"
    );
    assert!(
        backend.injected().is_empty(),
        "nothing reached the wire on an out-of-scope refusal"
    );
}

#[test]
fn inject_count_zero_is_a_no_op() {
    // `l4.inject(..., 0)` with an explicit count of 0 sends nothing — the loop is
    // `0..count`, not `.max(1)`, so an explicit zero is a deliberate no-op (an
    // absent count still defaults to 1).
    let backend = MockBackend::with_replies(vec![]);
    let lang = L4Language::new(
        loopback_guard(true),
        backend.clone(),
        Arc::new(InMemoryL4FlowStore::new()),
        false,
    );
    let engine =
        build_engine_with_languages(&RhaiLimits::default(), Duration::from_secs(5), &[&lang])
            .expect("engine builds");
    let script = r#"
        let spec = #{ layers: [ #{ ipv4: #{ dst: "127.0.0.1" } }, #{ udp: #{ dst_port: 9 } } ] };
        l4.inject(spec, "127.0.0.1", "lo", 0)
    "#;
    let out = engine
        .eval::<rhai::Dynamic>(script)
        .expect("inject with count:0 runs and is a no-op");
    let map = out.try_cast::<rhai::Map>().expect("inject returns a map");
    let sent = map
        .get("sent")
        .expect("sent field")
        .clone()
        .as_int()
        .expect("sent is an int");
    assert_eq!(sent, 0, "an explicit count:0 sends zero packets");
    assert!(
        backend.injected().is_empty(),
        "count:0 puts nothing on the wire"
    );
}

// ===========================================================================
// AC5 — the native l4: PoC step
// ===========================================================================

/// The normative `l4:` step body from the spec (scapy-style, human-readable).
const L4_STEP_BODY: &str = r#"
op: send_recv
packet:
  layers:
    - ipv4: { dst: "{{target_ip}}" }
    - tcp:  { dport: 80, flags: S }
timeout_ms: 1000
"#;

#[test]
fn ac5_l4_step_body_round_trips() {
    let body: serde_yaml::Value = serde_yaml::from_str(L4_STEP_BODY).expect("body parses");
    assert_eq!(body.get("op").and_then(|v| v.as_str()), Some("send_recv"));
    assert_eq!(
        body.get("timeout_ms").and_then(serde_yaml::Value::as_u64),
        Some(1000)
    );
    let layers = body
        .get("packet")
        .and_then(|p| p.get("layers"))
        .and_then(|l| l.as_sequence())
        .expect("packet.layers");
    assert_eq!(layers.len(), 2);

    // YAML → model → YAML → model is stable.
    let reserialized = serde_yaml::to_string(&body).expect("serialize");
    let parsed: serde_yaml::Value = serde_yaml::from_str(&reserialized).expect("re-parse");
    assert_eq!(body, parsed, "the l4: step body round-trips");
}

#[test]
fn ac5_send_recv_step_binds_packet_tcp_flags() {
    // In-scope loopback target, a SYN-ACK reply replayed by the mock.
    let lang = L4Language::new(
        loopback_guard(true),
        MockBackend::with_replies(vec![synack_reply()]),
        Arc::new(InMemoryL4FlowStore::new()),
        false,
    );
    let handler = lang.poc_step().expect("l4 contributes a poc step");

    let body: serde_yaml::Value = serde_yaml::from_str(L4_STEP_BODY).expect("body");
    let mut vars = BTreeMap::new();
    vars.insert("target_ip".to_string(), Value::Str("127.0.0.1".to_string()));

    let outcome = handler
        .run(&body, &PocStepInputs { vars })
        .expect("the in-scope l4: step runs");

    // The `packet` source is dotted-walkable: `field: tcp.flags` resolves to "SA",
    // so a sibling `extract { type: packet, field: tcp.flags }` + the `dsl`
    // `synack_flags == "SA"` success assertion pass (the runner does the walk).
    let packet = outcome
        .sources
        .get("packet")
        .expect("packet source present");
    assert_eq!(
        pluck(packet, "tcp.flags"),
        Some(Value::Str("SA".to_string())),
        "a SYN-ACK reply's tcp.flags renders scapy-style",
    );
    assert_eq!(
        outcome.bindings.get("l4_outcome"),
        Some(&Value::Str("response".to_string()))
    );
}

#[test]
fn ac5_out_of_scope_target_is_refused() {
    // The same step, but targeting a host no scope entry covers: the shared
    // L4Guard refuses (deny-by-default), nothing reaches the wire.
    let backend = MockBackend::with_replies(vec![]);
    let lang = L4Language::new(
        loopback_guard(true),
        backend.clone(),
        Arc::new(InMemoryL4FlowStore::new()),
        false,
    );
    let handler = lang.poc_step().expect("poc step");

    let body: serde_yaml::Value = serde_yaml::from_str(L4_STEP_BODY).expect("body");
    let mut vars = BTreeMap::new();
    vars.insert("target_ip".to_string(), Value::Str("10.9.9.9".to_string()));

    let err = handler
        .run(&body, &PocStepInputs { vars })
        .expect_err("an out-of-scope target is refused");
    assert!(
        err.to_string().contains("out of L4 scope"),
        "the refusal must be the deny-by-default scope error, got: {err}"
    );
    assert!(backend.injected().is_empty(), "nothing reached the wire");
}

/// Walk a dotted field into a `Value` object — the same semantics as the PoC
/// runner's `pluck_field`, so this test proves the shape the runner consumes.
fn pluck(source: &Value, field: &str) -> Option<Value> {
    let mut cur = source;
    for seg in field.split('.').filter(|s| !s.is_empty()) {
        match cur {
            Value::Object(m) => cur = m.get(seg)?,
            _ => return None,
        }
    }
    Some(cur.clone())
}

// ===========================================================================
// AC8 — one vocabulary across the three faces
// ===========================================================================

#[test]
fn ac8_one_vocabulary_across_catalog_poc_rhai_and_commands() {
    let lang = L4Language::for_catalog();
    let catalog = lang.catalog();

    // (1) catalog host-fn names
    let catalog_names: BTreeSet<String> = catalog.host_fns.iter().map(|f| f.name.clone()).collect();

    // (2) the l4: step `op` verb vocabulary — the WIRE SUBSET of the shared
    // vocabulary (a one-shot step runs only craft/inject/send_recv), not the full
    // host-fn set. The invariant is *consistent subset*, never a divergent set.
    let op_verbs: BTreeSet<String> = catalog
        .poc_step
        .as_ref()
        .expect("l4 contributes a poc step")
        .enums
        .get("op")
        .expect("the l4: step has an `op` enum")
        .iter()
        .cloned()
        .collect();

    // (3) the host fns aitm-plugin-rhai actually registered for the `l4` namespace
    let registered: BTreeSet<String> = registered_host_fns(&[&lang])
        .expect("l4 registers")
        .into_iter()
        .filter(|(ns, _)| ns == "l4")
        .map(|(_, name)| name)
        .collect();

    // The step op set is a subset of — and every op is a real member of — the one
    // shared host-fn vocabulary (AC8: consistent subset, not divergence).
    assert!(
        op_verbs.is_subset(&catalog_names),
        "every l4: step op must be a real catalog host-fn (consistent subset)"
    );
    assert_eq!(
        op_verbs,
        BTreeSet::from([
            "craft".to_string(),
            "inject".to_string(),
            "send_recv".to_string()
        ]),
        "the l4: step exposes exactly the three wire verbs"
    );
    assert_eq!(
        catalog_names, registered,
        "catalog host-fns == Rhai-registered l4.* host fns"
    );
    assert!(!catalog_names.is_empty(), "the l4 vocabulary is non-empty");

    // Each scripting verb is a real `l4.<verb>` command on the bus — the shared
    // vocabulary meets the command surface (reconciliation interlock #3).
    let mut reg = aitm_core::Registry::new();
    reg.add_plugin(Box::new(L4Module::with_privilege(
        &L4Config::default(),
        L4Privilege::available(),
    )));
    for verb in &catalog_names {
        let cmd = format!("l4.{verb}");
        assert!(
            reg.command(&cmd).is_some(),
            "scripting verb `{cmd}` must be a registered l4.* command"
        );
    }
}

#[test]
fn ac8_production_catalog_ships_l4() {
    // The shipped catalog (production_languages) carries the same l4 vocabulary,
    // so operator completion gains it as data.
    let langs = production_languages();
    let l4 = langs
        .iter()
        .find(|l| l.namespace() == "l4")
        .expect("l4 is a production language");
    assert_eq!(l4.api_version(), "0.1.0");
    assert!(
        l4.catalog().host_fns.iter().any(|f| f.name == "send_recv"),
        "the shipped l4 catalog advertises send_recv"
    );
}
