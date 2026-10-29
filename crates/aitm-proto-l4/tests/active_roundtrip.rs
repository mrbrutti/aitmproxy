//! M5 exit gate — the active wire round-trip, driven end-to-end through the public
//! module + registry over a real scoped loopback (M5 plan Task 15).
//!
//! These are the headline functional proofs (AC9/AC10/AC11) exercised the way an
//! operator reaches them: the assembled [`L4Module`] loaded into a core [`Registry`],
//! driven by command name with a real libpcap backend. They are **privilege-gated**:
//! `#[ignore]`d, run only with `AITM_L4_TESTS=1`, and — when the host lacks raw
//! capture/inject privilege — they skip cleanly on `L4Unavailable` rather than
//! failing. Loopback raw inject needs an L2 frame, so they are Linux-only (matching
//! `commands::sendrecv`'s real-pcap suite); macOS skips.
//!
//! The hermetic command-level proofs (mock backend) live beside each command
//! (`commands/inject.rs`, `commands/sendrecv.rs`); these add the real-wire,
//! fully-assembled path the unit tests cannot.

use aitm_core::{
    CommandHost, HttpFlow, HttpRequest, MemFlowStore, Params, ProxyClient, Registry, ScopeEntry,
    ScopeRateGuard, StdGuard, Value,
};
use aitm_proto_l4::config::L4Config;
use aitm_proto_l4::{L4Error, L4Module, L4Privilege};
use futures::future::BoxFuture;

const IFACE: &str = "lo";

struct StubClient;
impl ProxyClient for StubClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

/// Whether the privileged active-wire suite should run on this host.
fn active_enabled() -> bool {
    !cfg!(target_os = "macos") && std::env::var("AITM_L4_TESTS").ok().as_deref() == Some("1")
}

/// `true` if an error is the fail-closed "no privilege / libpcap" signal, so the test
/// should skip rather than fail.
fn is_unavailable(err: &anyhow::Error) -> bool {
    matches!(err.downcast_ref::<L4Error>(), Some(L4Error::Unavailable(_)))
}

fn obj(fields: Vec<(&str, Value)>) -> Value {
    Value::Object(
        fields
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    )
}

fn params(fields: Vec<(&str, Value)>) -> Params {
    Params::new(
        fields
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    )
}

/// An Ethernet/IPv4/UDP/Raw craft spec (full L2 frame) in the `Value` shape the wire
/// commands accept. The empty `ether` layer fills defaults (ethertype from the IPv4
/// layer), so the frame is wire-valid on loopback.
fn udp_frame_spec(dst_port: i64, payload: &[u8]) -> Value {
    obj(vec![(
        "layers",
        Value::Array(vec![
            obj(vec![("ether", obj(vec![]))]),
            obj(vec![(
                "ipv4",
                obj(vec![
                    ("src", Value::Str("127.0.0.1".into())),
                    ("dst", Value::Str("127.0.0.1".into())),
                ]),
            )]),
            obj(vec![("udp", obj(vec![("dst_port", Value::Int(dst_port))]))]),
            obj(vec![(
                "raw",
                Value::Array(payload.iter().map(|b| Value::Int(i64::from(*b))).collect()),
            )]),
        ]),
    )])
}

/// A module with privilege assumed present (so the wire verbs are not gated and the
/// real libpcap backend is exercised; it still fails closed at call time without OS
/// privilege), loaded into a registry.
fn registry() -> Registry {
    let cfg = L4Config {
        enabled: true,
        ..L4Config::default()
    };
    let module = L4Module::with_privilege(&cfg, L4Privilege::available());
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(module));
    reg
}

/// The core SSRF/scope guard with loopback admitted, so the defense-in-depth
/// `check_active` lets the loopback target through.
fn core_guard() -> StdGuard {
    let g = StdGuard::default();
    g.add_scope(ScopeEntry {
        host: "127.0.0.1".into(),
    });
    g
}

/// Add an L4 scope entry through the real `l4.scope.add` command.
fn add_scope(reg: &Registry, host: &CommandHost, capability: &str, direction: &str) {
    reg.command("l4.scope.add")
        .expect("l4.scope.add registered")
        .invoke(
            params(vec![
                ("cidr", Value::Str("127.0.0.0/8".into())),
                ("interface", Value::Str(IFACE.into())),
                ("direction", Value::Str(direction.into())),
                ("capability", Value::Str(capability.into())),
                ("ports", Value::Str("*".into())),
                ("inject_rate_pps", Value::Int(100)),
            ]),
            host,
        )
        .expect("scope.add ok");
}

/// AC9 — the active round-trip through the assembled registry: scope loopback for
/// inject, craft + inject a real frame, and read the recorded flow back via
/// `l4.flow.get` with `injected = true`. Skips cleanly without privilege.
#[test]
#[ignore = "requires raw-inject privilege; run with AITM_L4_TESTS=1 and -- --ignored (Linux)"]
fn active_roundtrip_via_registry() {
    if !active_enabled() {
        return;
    }
    let reg = registry();
    let store = MemFlowStore::new();
    let client = StubClient;
    let guard = core_guard();
    let host = CommandHost::new(&store, &client, &guard, None);

    add_scope(&reg, &host, "inject", "outbound");

    let injected = reg
        .command("l4.inject")
        .expect("l4.inject registered")
        .invoke(
            params(vec![
                ("spec", udp_frame_spec(9, b"probe")),
                ("dst", Value::Str("127.0.0.1".into())),
                ("interface", Value::Str(IFACE.into())),
                ("port", Value::Int(9)),
                ("count", Value::Int(1)),
            ]),
            &host,
        );
    let result = match injected {
        Ok(v) => v,
        Err(e) if is_unavailable(&e) => return, // no privilege on this host — skip
        Err(e) => panic!("l4.inject failed for a non-privilege reason: {e:?}"),
    };

    let Value::Object(result) = result else {
        panic!("l4.inject returns an object");
    };
    assert_eq!(result.get("sent"), Some(&Value::Int(1)));
    let Some(Value::Str(flow_id)) = result.get("flow_id") else {
        panic!("l4.inject returns a flow id");
    };

    // Read the injected packet back through the command surface (AC9: via l4.flow.get).
    let got = reg
        .command("l4.flow.get")
        .expect("l4.flow.get registered")
        .invoke(params(vec![("id", Value::Str(flow_id.clone()))]), &host)
        .expect("flow.get ok");
    let Value::Object(got) = got else {
        panic!("l4.flow.get returns an object");
    };
    assert_eq!(got.get("kind"), Some(&Value::Str("craft".into())));
    assert_eq!(
        got.get("injected_count"),
        Some(&Value::Int(1)),
        "the round-trip flow holds the injected packet (injected = true)"
    );
}

/// AC11 — `l4.send_recv` with no responder returns a `no_response` outcome after the
/// timeout and never hangs, driven through the assembled registry over the real wire.
/// (AC10's response path is proven hermetically in `commands/sendrecv.rs`.) Skips
/// cleanly without privilege.
#[test]
#[ignore = "requires raw-inject/capture privilege; run with AITM_L4_TESTS=1 and -- --ignored (Linux)"]
fn send_recv_silence_via_registry() {
    if !active_enabled() {
        return;
    }
    let reg = registry();
    let store = MemFlowStore::new();
    let client = StubClient;
    let guard = core_guard();
    let host = CommandHost::new(&store, &client, &guard, None);

    add_scope(&reg, &host, "inject", "outbound");
    add_scope(&reg, &host, "capture", "inbound");

    // A port with no responder, a short timeout: must return (not hang) with
    // no_response.
    let result = reg
        .command("l4.send_recv")
        .expect("l4.send_recv registered")
        .invoke(
            params(vec![
                ("spec", udp_frame_spec(9, b"probe")),
                ("dst", Value::Str("127.0.0.1".into())),
                ("interface", Value::Str(IFACE.into())),
                ("port", Value::Int(9)),
                ("timeout_ms", Value::Int(300)),
            ]),
            &host,
        );
    let result = match result {
        Ok(v) => v,
        Err(e) if is_unavailable(&e) => return, // no privilege — skip
        Err(e) => panic!("l4.send_recv failed for a non-privilege reason: {e:?}"),
    };

    let Value::Object(result) = result else {
        panic!("l4.send_recv returns an object");
    };
    let Some(Value::Object(outcome)) = result.get("outcome") else {
        panic!("l4.send_recv returns an outcome");
    };
    assert_eq!(
        outcome.get("kind"),
        Some(&Value::Str("no_response".into())),
        "no responder ⇒ no_response (and the command returned, so it did not hang)"
    );
}
