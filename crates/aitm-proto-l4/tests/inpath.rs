//! M5 exit gate — in-path interception, driven through the public module + registry
//! (M5 plan Task 15).
//!
//! - **AC16 / AC18 (runs anywhere):** the assembled `l4.intercept.start` is reachable
//!   on the bus and fails closed with a typed `L4Unavailable` when in-path privilege
//!   (Linux `CAP_NET_ADMIN`) is absent — proven hermetically so it runs on this host.
//! - **AC12 / AC13 (Linux + `AITM_L4_INPATH`):** against a real loopback `nft` queue, a
//!   parked packet mutated + forwarded is delivered mangled, and a dropped packet is
//!   not delivered — driven through the fully-assembled registry. Skips cleanly off
//!   Linux / without privilege.
//!
//! The command-layer proofs of the same behaviour (hermetic mock backend, and the
//! real NFQUEUE suite) live in `src/commands/intercept.rs`; these add the
//! fully-assembled registry path.

use std::time::{Duration, Instant};

use aitm_core::{
    CommandHost, HttpFlow, HttpRequest, MemFlowStore, Params, ProxyClient, Registry, ScopeEntry,
    ScopeRateGuard, StdGuard, Value,
};
use aitm_proto_l4::config::{InterceptConfig, L4Config, Verdict};
use aitm_proto_l4::{L4Error, L4Module, L4Privilege};
use futures::future::BoxFuture;

const IFACE: &str = "lo";

struct StubClient;
impl ProxyClient for StubClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

fn inpath_enabled() -> bool {
    cfg!(target_os = "linux") && std::env::var("AITM_L4_INPATH").ok().as_deref() == Some("1")
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

fn enabled_cfg(queue_num: u16) -> L4Config {
    L4Config {
        enabled: true,
        intercept: Some(InterceptConfig {
            queue_num,
            verdict_timeout: Duration::from_secs(5),
            on_timeout: Verdict::Forward,
            max_parked: 256,
            on_overflow: Verdict::Forward,
        }),
        // Drives the real `l4.scope.add` round-trip ⇒ opt into runtime widening.
        allow_agent_widen: true,
        ..L4Config::default()
    }
}

fn registry(module: L4Module) -> Registry {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(module));
    reg
}

fn core_guard() -> StdGuard {
    let g = StdGuard::default();
    g.add_scope(ScopeEntry {
        host: "127.0.0.1".into(),
    });
    g
}

/// AC16 / AC18 — the in-path surface is reachable through the assembled registry and
/// fails closed when in-path privilege is absent. Hermetic: forces the "no
/// CAP_NET_ADMIN" state, so it runs on any host (macOS included).
#[test]
fn intercept_start_fail_closed_via_registry() {
    let unprivileged = L4Privilege {
        capture_inject: None,
        intercept: Some("missing CAP_NET_ADMIN".into()),
    };
    let module = L4Module::with_privilege(&enabled_cfg(0), unprivileged);
    let reg = registry(module);

    assert!(
        reg.command("l4.intercept.start").is_some(),
        "l4.intercept.start must be on the bus (AC18)"
    );

    let store = MemFlowStore::new();
    let client = StubClient;
    let guard = core_guard();
    let host = CommandHost::new(&store, &client, &guard, None);

    let err = reg
        .command("l4.intercept.start")
        .unwrap()
        .invoke(
            params(vec![
                ("interface", Value::Str(IFACE.into())),
                ("queue_num", Value::Int(0)),
            ]),
            &host,
        )
        .expect_err("intercept.start must fail closed without CAP_NET_ADMIN");
    let l4 = err
        .downcast_ref::<L4Error>()
        .unwrap_or_else(|| panic!("want a typed L4Error, got {err:?}"));
    assert!(
        matches!(l4, L4Error::Unavailable(_)),
        "in-path must fail closed with L4Unavailable, got {l4:?}"
    );

    // L4PAR-AC4 / AC9 (plan A4): `l4.intercept.status` is not privilege-gated. It
    // answers `Ok` with `available: false` and the same reason the start refused with.
    let status = reg
        .command("l4.intercept.status")
        .expect("l4.intercept.status must be on the bus")
        .invoke(Params::default(), &host)
        .expect("intercept.status must answer Ok without CAP_NET_ADMIN");
    let Value::Object(fields) = &status else {
        panic!("intercept.status must be an object, got {status:?}");
    };
    assert_eq!(fields.get("available"), Some(&Value::Bool(false)));
    assert_eq!(
        fields.get("reason"),
        Some(&Value::Str("missing CAP_NET_ADMIN".into()))
    );
    assert_eq!(fields.get("sessions"), Some(&Value::Array(vec![])));
}

// ---- Linux-gated functional suite (real NFQUEUE on a loopback nft queue) ---------

/// Install / tear down a loopback `nft` rule steering UDP to `dport` into `queue`.
fn nft(args: &[&str]) -> bool {
    std::process::Command::new("nft")
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Poll `f` until true or a 5s deadline (the parked packet arrives asynchronously).
fn wait_until(mut f: impl FnMut() -> bool, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("timed out waiting for {what}");
}

/// The parked-packet ids currently listed through `l4.intercept.list`.
fn parked_ids(reg: &Registry, host: &CommandHost) -> Vec<String> {
    let Value::Array(items) = reg
        .command("l4.intercept.list")
        .expect("l4.intercept.list registered")
        .invoke(Params::default(), host)
        .expect("list ok")
    else {
        panic!("list returns an array");
    };
    items
        .into_iter()
        .filter_map(|v| match v {
            Value::Object(o) => match o.get("id") {
                Some(Value::Str(s)) => Some(s.clone()),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// A mangled IPv4/UDP/Raw frame (no Ethernet — NFQUEUE reinjects at the IP layer),
/// crafted through the real `l4.craft` command, returned as its wire bytes.
fn craft_ip_udp(
    reg: &Registry,
    host: &CommandHost,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let spec = obj(vec![(
        "layers",
        Value::Array(vec![
            obj(vec![(
                "ipv4",
                obj(vec![
                    ("src", Value::Str("127.0.0.1".into())),
                    ("dst", Value::Str("127.0.0.1".into())),
                ]),
            )]),
            obj(vec![(
                "udp",
                obj(vec![
                    ("src_port", Value::Int(i64::from(src_port))),
                    ("dst_port", Value::Int(i64::from(dst_port))),
                ]),
            )]),
            obj(vec![(
                "raw",
                Value::Array(payload.iter().map(|b| Value::Int(i64::from(*b))).collect()),
            )]),
        ]),
    )]);
    let crafted = reg
        .command("l4.craft")
        .expect("l4.craft registered")
        .invoke(params(vec![("spec", spec)]), host)
        .expect("craft ok");
    let Value::Object(crafted) = crafted else {
        panic!("craft returns an object");
    };
    match crafted.get("bytes") {
        Some(Value::Bytes(b)) => b.clone(),
        other => panic!("craft must return bytes, got {other:?}"),
    }
}

/// Assemble an enabled, privilege-present module + a scoped loopback `nft` queue, and
/// start interception through the registry. Returns the parked id of the datagram the
/// caller sends, plus a teardown closure. Shared by the mutate-forward and drop tests.
fn start_and_park(reg: &Registry, host: &CommandHost, queue: u16, table: &str, dport: u16) {
    let _ = nft(&["delete", "table", "inet", table]);
    assert!(nft(&["add", "table", "inet", table]), "nft add table");
    assert!(
        nft(&[
            "add", "chain", "inet", table, "out", "{", "type", "filter", "hook", "output",
            "priority", "0", ";", "}",
        ]),
        "nft add chain"
    );
    assert!(
        nft(&[
            "add",
            "rule",
            "inet",
            table,
            "out",
            "ip",
            "daddr",
            "127.0.0.1",
            "udp",
            "dport",
            &dport.to_string(),
            "queue",
            "num",
            &queue.to_string(),
        ]),
        "nft add rule"
    );

    // Scope loopback for Intercept, then start through the assembled registry.
    reg.command("l4.scope.add")
        .expect("l4.scope.add registered")
        .invoke(
            params(vec![
                ("cidr", Value::Str("127.0.0.1/32".into())),
                ("interface", Value::Str(IFACE.into())),
                ("direction", Value::Str("outbound".into())),
                ("capability", Value::Str("intercept".into())),
                ("ports", Value::Str("*".into())),
                ("inject_rate_pps", Value::Int(100)),
            ]),
            host,
        )
        .expect("scope.add ok");
    reg.command("l4.intercept.start")
        .expect("l4.intercept.start registered")
        .invoke(
            params(vec![
                ("interface", Value::Str(IFACE.into())),
                ("queue_num", Value::Int(i64::from(queue))),
            ]),
            host,
        )
        .expect("intercept.start binds the queue");
}

/// AC12 (Linux + `AITM_L4_INPATH`) — a parked packet mutated via `l4.intercept.mutate`
/// then forwarded via `l4.intercept.forward` is delivered **mangled**, all through the
/// assembled registry.
#[test]
#[ignore = "privileged + Linux NFQUEUE; run as root with AITM_L4_INPATH=1 and -- --ignored"]
fn inpath_mutate_forward_via_registry() {
    if !inpath_enabled() {
        return;
    }
    use std::net::UdpSocket;

    const QUEUE: u16 = 2114;
    let table = "aitm_t15_fwd";

    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let dport = receiver.local_addr().unwrap().port();

    let module = L4Module::with_privilege(&enabled_cfg(QUEUE), L4Privilege::available());
    let reg = registry(module);
    let store = MemFlowStore::new();
    let client = StubClient;
    let guard = core_guard();
    let host = CommandHost::new(&store, &client, &guard, None);

    start_and_park(&reg, &host, QUEUE, table, dport);

    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let sport = sender.local_addr().unwrap().port();
    sender
        .send_to(b"ORIGINAL", ("127.0.0.1", dport))
        .expect("send original");

    wait_until(|| !parked_ids(&reg, &host).is_empty(), "the packet to park");
    let id = parked_ids(&reg, &host).remove(0);

    let mangled = craft_ip_udp(&reg, &host, sport, dport, b"MANGLED!");
    reg.command("l4.intercept.mutate")
        .expect("l4.intercept.mutate registered")
        .invoke(
            params(vec![
                ("id", Value::Str(id.clone())),
                ("bytes", Value::Bytes(mangled)),
            ]),
            &host,
        )
        .expect("mutate ok");
    assert_eq!(
        reg.command("l4.intercept.forward")
            .expect("l4.intercept.forward registered")
            .invoke(params(vec![("id", Value::Str(id))]), &host)
            .expect("forward ok"),
        Value::Bool(true)
    );

    let mut buf = [0u8; 64];
    let n = receiver
        .recv(&mut buf)
        .expect("receiver gets the forwarded packet");
    assert_eq!(
        &buf[..n],
        b"MANGLED!",
        "the delivered packet is the mutation"
    );

    let _ = nft(&["delete", "table", "inet", table]);
}

/// AC13 (Linux + `AITM_L4_INPATH`) — a parked packet given `l4.intercept.drop` is
/// **not delivered**: the receiver times out. Driven through the assembled registry.
#[test]
#[ignore = "privileged + Linux NFQUEUE; run as root with AITM_L4_INPATH=1 and -- --ignored"]
fn inpath_drop_via_registry() {
    if !inpath_enabled() {
        return;
    }
    use std::net::UdpSocket;

    const QUEUE: u16 = 2115;
    let table = "aitm_t15_drop";

    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let dport = receiver.local_addr().unwrap().port();

    let module = L4Module::with_privilege(&enabled_cfg(QUEUE), L4Privilege::available());
    let reg = registry(module);
    let store = MemFlowStore::new();
    let client = StubClient;
    let guard = core_guard();
    let host = CommandHost::new(&store, &client, &guard, None);

    start_and_park(&reg, &host, QUEUE, table, dport);

    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    sender
        .send_to(b"ORIGINAL", ("127.0.0.1", dport))
        .expect("send original");

    wait_until(|| !parked_ids(&reg, &host).is_empty(), "the packet to park");
    let id = parked_ids(&reg, &host).remove(0);

    assert_eq!(
        reg.command("l4.intercept.drop")
            .expect("l4.intercept.drop registered")
            .invoke(params(vec![("id", Value::Str(id))]), &host)
            .expect("drop ok"),
        Value::Bool(true)
    );

    let mut buf = [0u8; 64];
    assert!(
        receiver.recv(&mut buf).is_err(),
        "a dropped packet must not be delivered"
    );

    let _ = nft(&["delete", "table", "inet", table]);
}
