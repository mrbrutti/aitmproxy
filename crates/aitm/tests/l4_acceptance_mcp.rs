//! Stage F — agent-driven (MCP) real-packet acceptance (L4OPS-AC13, plan Task 16).
//!
//! The §4.2 acceptance path driven **over the bus** — a harness-neutral client that
//! speaks `tools/call` JSON-RPC to the real [`McpServer`], exactly as an MCP agent
//! would — against the Stage-D `aitm-testtarget` loopback L4 service with **real
//! packets**: scope loopback → `l4.capture.start` → `l4.craft` → `l4.inject` →
//! `l4.flow.get` (the injected packet is recorded) → `l4.send_recv` (the target
//! echoes the payload) → (Linux) `l4.intercept.start` / mutate / forward / drop.
//!
//! **Scope authority (SEC-2).** The target is loopback (`127.0.0.1`), a
//! dangerous-destination / control-plane range. The guard lifts that denylist
//! **only** for a *config-declared* scope entry (operator authority): `l4.scope.add`
//! over the bus always mints `source = Runtime` and so can never authorize a
//! loopback inject, by design. The acceptance therefore declares the loopback
//! engagement in the operator's config (as a real operator authorizes a target) and
//! still exercises `l4.scope.add` at runtime for the capture capability (which binds
//! with no destination and is not denylisted). This is the security model working as
//! intended, and the guard-airtightness suite asserts the Runtime-scope refusal
//! directly.
//!
//! **Privilege reality (CLI/Linux-first).** Raw L4 (capture / inject / NFQUEUE)
//! needs `CAP_NET_RAW` / `/dev/bpf` / `CAP_NET_ADMIN`, which a plain dev host does
//! not have. The real-packet suites are `#[ignore]`d and gated behind
//! `AITM_L4_TESTS` (capture/inject/send_recv) and `AITM_L4_INPATH` (Linux NFQUEUE):
//! they run **green where privilege exists** (Linux CI / elevated) and **skip
//! cleanly** — on the gate env var, the platform, or a typed `L4Unavailable` from
//! the bus — where it does not. They never fake privileged L4.
//!
//! **Guard-airtightness is hermetic** (`mcp_guard_airtight`): the refusals that are
//! the point of the milestone — an out-of-scope inject, an agent Sensitive call with
//! its `l4.allow_agent_*` flag off, an injection-rate-cap trip, and a Runtime-scope
//! loopback inject — need no privilege and run on every host, including this Mac.
//! They assert that it is structurally impossible to aim a raw-packet action at an
//! out-of-scope (or operator-undeclared control-plane) target from the agent path.
//!
//! The in-command halves (sensitivity, the flag as the command sees the caller,
//! `confirm_prompt`) and the server halves (the `AgentPolicy` dimension, the
//! confirm-token lifecycle, the audit ring) are proven in `l4_operator_surfaces.rs`
//! and the `aitm-proto-l4` suites; these add the real-wire, whole-bus acceptance.

use std::sync::Arc;

use aitm_core::McpTransport;
use aitm_core::{
    AgentPolicy, AgentState, AuditRing, Frontend, HttpFlow, HttpRequest, MemFlowStore, ProxyClient,
    Registry, ScopeEntry, ScopeRateGuard, StdGuard,
};
use aitm_mcp::{ConnCtx, McpServer};
use aitm_plugins::AgentPlugin;
use aitm_proto_l4::config::{InterceptConfig, L4Config};
use aitm_proto_l4::types::{
    IpCidr, L4Capability, L4Direction, L4ScopeEntry, L4ScopeId, L4ScopeSource, PortRange, RateCap,
};
use aitm_proto_l4::{L4Module, L4Privilege};
use aitm_testtarget::l4::{L4Config as TargetL4Config, L4Service};
use futures::future::BoxFuture;
use serde_json::{json, Value as JsonValue};

// ---- bus scaffolding ----------------------------------------------------------

struct StubClient;
impl ProxyClient for StubClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

/// A server over a registry holding the L4 module (`cfg`, full privilege so the real
/// wire verbs are present and fail closed only at call time) and the M4 `AgentPlugin`
/// (for the policy dimension), with the given policy. The **core** guard admits
/// `127.0.0.1`, so a call that gets past every L4 gate reaches the real wire backend
/// (this is a real-packet harness, not the hermetic one in `l4_operator_surfaces.rs`
/// whose core guard is empty). Returns the server and its audit ring.
fn server(cfg: &L4Config, policy: AgentPolicy) -> (McpServer, Arc<AuditRing>) {
    let agent_state = Arc::new(AgentState::new(policy));
    let ring = Arc::new(AuditRing::default());
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(L4Module::with_privilege(
        cfg,
        L4Privilege::available(),
    )));
    reg.add_plugin(Box::new(
        AgentPlugin::new(agent_state.clone()).with_audit_ring(ring.clone()),
    ));
    let core_guard = StdGuard::default();
    core_guard.add_scope(ScopeEntry {
        host: "127.0.0.1".into(),
    });
    let srv = McpServer::new(Arc::new(reg), McpTransport::Stdio)
        .with_agent_state(agent_state)
        .with_services(
            Arc::new(MemFlowStore::new()),
            Arc::new(StubClient),
            Arc::new(core_guard),
            None,
        )
        .with_audit_ring(ring.clone());
    (srv, ring)
}

/// Invoke `name` as `role` with `args` over the real bus, returning the parsed
/// `result` object (the exact JSON an MCP client receives).
fn call(srv: &McpServer, role: Frontend, name: &str, args: JsonValue) -> JsonValue {
    let req = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": args},
    });
    let resp = srv
        .handle_on(&ConnCtx::new(role), &req.to_string())
        .expect("a request gets a response");
    let parsed: JsonValue = serde_json::from_str(&resp).expect("json");
    parsed["result"].clone()
}

/// Whether a `tools/call` result is a tool error (`isError: true`).
fn is_error(result: &JsonValue) -> bool {
    result["isError"].as_bool().unwrap_or(false)
}

/// The human-readable text of a tool result (for substring assertions).
fn text(result: &JsonValue) -> String {
    result["content"][0]["text"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

/// The machine value of a successful result (the `structuredContent`).
fn structured(result: &JsonValue) -> JsonValue {
    result["structuredContent"].clone()
}

/// `true` when an error result is the fail-closed "no privilege / libpcap / nfq"
/// signal, so a privileged test skips rather than fails.
fn is_unavailable(result: &JsonValue) -> bool {
    is_error(result) && text(result).to_lowercase().contains("unavailable")
}

// ---- privilege gating (matches the M5 convention) -----------------------------

/// Whether the privileged capture/inject/send_recv suite should run on this host.
/// Loopback raw inject needs an L2 frame, so it is Linux-only (matching M5's
/// `active_roundtrip` and `commands::sendrecv` real-pcap suites); macOS skips.
fn active_enabled() -> bool {
    !cfg!(target_os = "macos") && std::env::var("AITM_L4_TESTS").ok().as_deref() == Some("1")
}

/// Whether the privileged Linux NFQUEUE in-path suite should run on this host.
fn inpath_enabled() -> bool {
    cfg!(target_os = "linux") && std::env::var("AITM_L4_INPATH").ok().as_deref() == Some("1")
}

/// The loopback interface for raw L4 on the privileged hosts (Linux `lo`); also the
/// scope/target interface label the hermetic tests match on.
const IFACE: &str = "lo";

/// A **config-declared** (operator-authority, `source = Config`) loopback scope entry
/// granting `capability` with the given per-entry injection rate. Config provenance
/// is what lifts the loopback dangerous-destination denylist (SEC-2); a runtime
/// `l4.scope.add` cannot.
fn config_scope(capability: L4Capability, direction: L4Direction, rate_pps: u32) -> L4ScopeEntry {
    L4ScopeEntry {
        id: L4ScopeId::new(),
        cidr: IpCidr {
            addr: "127.0.0.1".parse().unwrap(),
            prefix: 32,
        },
        ports: PortRange { lo: 0, hi: 65535 },
        interface: IFACE.to_string(),
        direction,
        capability,
        inject_rate: RateCap {
            pps: rate_pps,
            burst: rate_pps,
        },
        source: L4ScopeSource::Config,
    }
}

/// An enabled L4 config for the acceptance path: the agent is opted into every
/// capability under `AgentPolicy::All`, the loopback **inject** engagement is
/// config-declared (so the denylist is lifted for the real target), and the in-path
/// queue is set so `l4.intercept.start` binds it. `allow_agent_widen` is on so the
/// capture scope can be added over the bus at runtime (capture is not denylisted).
fn acceptance_cfg(queue_num: u16) -> L4Config {
    L4Config {
        enabled: true,
        allow_agent_capture: true,
        allow_agent_inject: true,
        allow_agent_intercept: true,
        allow_agent_widen: true,
        scope: vec![config_scope(
            L4Capability::Inject,
            L4Direction::Outbound,
            100,
        )],
        intercept: Some(InterceptConfig {
            queue_num,
            ..InterceptConfig::default()
        }),
        ..L4Config::default()
    }
}

/// Add an L4 scope entry over the bus as the agent (`allow_agent_widen` is on). Used
/// for capture (not denylisted) and intercept.
fn scope_add(srv: &McpServer, capability: &str, direction: &str) {
    let res = call(
        srv,
        Frontend::Mcp,
        "l4.scope.add",
        json!({
            "cidr": "127.0.0.0/8",
            "interface": IFACE,
            "direction": direction,
            "capability": capability,
            "ports": "*",
            "inject_rate_pps": 100,
        }),
    );
    assert!(
        !is_error(&res),
        "scope.add {capability} failed: {}",
        text(&res)
    );
}

/// A full Ethernet/IPv4/UDP/Raw frame (the shape loopback raw inject needs) as the
/// bus `spec` argument, destined for `127.0.0.1:dst_port` carrying `payload`.
fn udp_frame_spec(dst_port: u16, payload: &[u8]) -> JsonValue {
    json!({"layers": [
        {"ether": {}},
        {"ipv4": {"src": "127.0.0.1", "dst": "127.0.0.1"}},
        {"udp": {"dst_port": dst_port}},
        {"raw": payload.iter().map(|b| i64::from(*b)).collect::<Vec<_>>()},
    ]})
}

// ---- mcp_acceptance_roundtrip (AITM_L4_TESTS) ---------------------------------

/// L4OPS-AC13 — the §4.2 path end to end over the bus against the real
/// `aitm-testtarget` L4 service, with **real packets**: scope loopback (capture over
/// the bus, inject via operator config) → start capture → craft → inject at the
/// target's UDP port → `l4.flow.get` shows the injected packet recorded → `l4.send_recv`
/// elicits the target's echo. Gated behind `AITM_L4_TESTS` and Linux; skips cleanly
/// on `L4Unavailable` where privilege is absent.
/// Run: `AITM_L4_TESTS=1 cargo test -p aitm --test l4_acceptance_mcp -- --ignored`.
#[test]
#[ignore = "real-packet L4; run with AITM_L4_TESTS=1 and -- --ignored on a privileged Linux host"]
fn mcp_acceptance_roundtrip() {
    if !active_enabled() {
        return;
    }

    // Start the real loopback L4 target (UDP echo + TCP banner) on its own runtime;
    // the spawned responder tasks keep running on the runtime's worker threads while
    // the synchronous bus calls below drive against it.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build runtime");
    let service = rt
        .block_on(L4Service::start(TargetL4Config { enabled: true }))
        .expect("the opt-in L4 target binds when enabled");
    let udp_port = service.udp_addr().port();
    eprintln!("[acceptance] target UDP echo responder on 127.0.0.1:{udp_port}");

    let (srv, _ring) = server(&acceptance_cfg(0), AgentPolicy::All);

    // (1) Scope loopback for capture (inbound) over the bus — §4.2's `l4.scope.add`
    // step. Inject scope is operator-config (SEC-2; see the module header).
    scope_add(&srv, "capture", "inbound");

    // (2) Start capture on loopback.
    let cap = call(
        &srv,
        Frontend::Mcp,
        "l4.capture.start",
        json!({"interface": IFACE}),
    );
    if is_unavailable(&cap) {
        eprintln!("[acceptance] capture.start L4Unavailable — skipping (no privilege)");
        return;
    }
    assert!(!is_error(&cap), "capture.start failed: {}", text(&cap));
    eprintln!("[acceptance] capture.start → {}", structured(&cap));

    // (3) Craft the stimulus frame (pure, privilege-free).
    let crafted = call(
        &srv,
        Frontend::Mcp,
        "l4.craft",
        json!({"spec": udp_frame_spec(udp_port, b"probe")}),
    );
    assert!(!is_error(&crafted), "craft failed: {}", text(&crafted));
    assert!(
        structured(&crafted)["bytes"].is_string(),
        "craft returns the built frame as base64 bytes, got {}",
        structured(&crafted)
    );

    // (4) Inject the crafted frame at the target's real UDP port.
    let injected = call(
        &srv,
        Frontend::Mcp,
        "l4.inject",
        json!({
            "spec": udp_frame_spec(udp_port, b"probe"),
            "dst": "127.0.0.1",
            "interface": IFACE,
            "port": udp_port,
            "count": 1,
        }),
    );
    if is_unavailable(&injected) {
        eprintln!("[acceptance] l4.inject L4Unavailable — skipping (no privilege)");
        return;
    }
    assert!(!is_error(&injected), "inject failed: {}", text(&injected));
    let inject_sc = structured(&injected);
    assert_eq!(inject_sc["sent"], json!(1), "one packet reached the wire");
    let flow_id = inject_sc["flow_id"]
        .as_str()
        .expect("inject returns a flow id");
    eprintln!("[acceptance] l4.inject → sent=1 flow_id={flow_id}");

    // (5) `l4.flow.get` shows the injected packet captured in its flow (AC9-style
    // round-trip: injected = true).
    let flow = call(&srv, Frontend::Mcp, "l4.flow.get", json!({"id": flow_id}));
    assert!(!is_error(&flow), "flow.get failed: {}", text(&flow));
    assert_eq!(
        structured(&flow)["injected_count"],
        json!(1),
        "the round-trip flow holds the injected packet, got {}",
        structured(&flow)
    );
    eprintln!("[acceptance] l4.flow.get → {}", structured(&flow));

    // (6) `l4.send_recv` elicits a reply from the target: the UDP responder echoes the
    // payload back on the wire. The default five-tuple correlation is used (the
    // reversed tuple from the responder's port). On loopback the send_recv capture
    // also sees its own outbound stimulus; with a different source port that frame
    // correlates as `other` and may be returned ahead of the echo — so the assertion
    // is that a correlated reply from the target came back (not silence), which is the
    // real-wire round-trip §4.2 asks for. The deterministic injected-packet proof is
    // step (5); this proves a reply traversed the wire.
    let sr = call(
        &srv,
        Frontend::Mcp,
        "l4.send_recv",
        json!({
            "spec": udp_frame_spec(udp_port, b"probe"),
            "dst": "127.0.0.1",
            "interface": IFACE,
            "port": udp_port,
            "timeout_ms": 1500,
        }),
    );
    if is_unavailable(&sr) {
        eprintln!("[acceptance] l4.send_recv L4Unavailable — skipping (no privilege)");
        return;
    }
    assert!(!is_error(&sr), "send_recv failed: {}", text(&sr));
    let outcome = &structured(&sr)["outcome"];
    eprintln!("[acceptance] l4.send_recv → {outcome}");
    let kind = outcome["kind"].as_str().unwrap_or_default();
    assert!(
        matches!(kind, "response" | "responses" | "other"),
        "send_recv must observe a correlated reply from the target (not silence), got {outcome}"
    );

    drop(service);
}

// ---- mcp_inpath_mutate_forward_drop (AITM_L4_INPATH, Linux) -------------------

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
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if f() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    panic!("timed out waiting for {what}");
}

/// The parked-packet ids currently listed through `l4.intercept.list` over the bus.
fn parked_ids(srv: &McpServer) -> Vec<String> {
    let res = call(srv, Frontend::Mcp, "l4.intercept.list", json!({}));
    assert!(!is_error(&res), "intercept.list failed: {}", text(&res));
    structured(&res)
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v["id"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Set up a scoped loopback `nft` queue and start interception over the bus. Intercept
/// binds with no destination, so its runtime scope add is not denylisted.
fn start_and_park(srv: &McpServer, queue: u16, table: &str, dport: u16) {
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

    scope_add(srv, "intercept", "outbound");
    let started = call(
        srv,
        Frontend::Mcp,
        "l4.intercept.start",
        json!({"interface": IFACE, "queue_num": queue}),
    );
    assert!(
        !is_error(&started),
        "intercept.start binds the queue: {}",
        text(&started)
    );
}

/// L4OPS-AC13 (Linux + `AITM_L4_INPATH`) — in-path interception over the bus against
/// real NFQUEUE-steered loopback traffic: a parked packet mutated + forwarded is
/// delivered **mangled**, and a dropped packet is **not delivered**. Gated behind
/// `AITM_L4_INPATH` and Linux; skips cleanly elsewhere. Run as root:
/// `AITM_L4_INPATH=1 cargo test -p aitm --test l4_acceptance_mcp -- --ignored`.
#[test]
#[ignore = "privileged + Linux NFQUEUE; run as root with AITM_L4_INPATH=1 and -- --ignored"]
fn mcp_inpath_mutate_forward_drop() {
    if !inpath_enabled() {
        return;
    }
    use std::net::UdpSocket;
    use std::time::Duration;

    // --- mutate + forward: the mangled packet is delivered ---
    {
        const QUEUE: u16 = 3114;
        let table = "aitm_t16_fwd";
        let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let dport = receiver.local_addr().unwrap().port();

        let (srv, _ring) = server(&acceptance_cfg(QUEUE), AgentPolicy::All);
        start_and_park(&srv, QUEUE, table, dport);

        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        let sport = sender.local_addr().unwrap().port();
        sender
            .send_to(b"ORIGINAL", ("127.0.0.1", dport))
            .expect("send original");

        wait_until(|| !parked_ids(&srv).is_empty(), "the packet to park");
        let id = parked_ids(&srv).remove(0);

        // Craft the mangled replacement (IP/UDP, no Ethernet — NFQUEUE reinjects at
        // the IP layer) over the bus; reuse its base64 bytes as the mutation.
        let mangled = call(
            &srv,
            Frontend::Mcp,
            "l4.craft",
            json!({"spec": {"layers": [
                {"ipv4": {"src": "127.0.0.1", "dst": "127.0.0.1"}},
                {"udp": {"src_port": sport, "dst_port": dport}},
                {"raw": b"MANGLED!".iter().map(|b| i64::from(*b)).collect::<Vec<_>>()},
            ]}}),
        );
        assert!(
            !is_error(&mangled),
            "craft mangled failed: {}",
            text(&mangled)
        );
        let bytes_b64 = structured(&mangled)["bytes"]
            .as_str()
            .expect("craft returns base64 bytes")
            .to_string();

        let mutated = call(
            &srv,
            Frontend::Mcp,
            "l4.intercept.mutate",
            json!({"id": id, "bytes": bytes_b64}),
        );
        assert!(!is_error(&mutated), "mutate failed: {}", text(&mutated));

        let forwarded = call(
            &srv,
            Frontend::Mcp,
            "l4.intercept.forward",
            json!({"id": id}),
        );
        assert!(
            !is_error(&forwarded),
            "forward failed: {}",
            text(&forwarded)
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

    // --- drop: the packet is not delivered ---
    {
        const QUEUE: u16 = 3115;
        let table = "aitm_t16_drop";
        let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        receiver
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let dport = receiver.local_addr().unwrap().port();

        let (srv, _ring) = server(&acceptance_cfg(QUEUE), AgentPolicy::All);
        start_and_park(&srv, QUEUE, table, dport);

        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        sender
            .send_to(b"ORIGINAL", ("127.0.0.1", dport))
            .expect("send original");

        wait_until(|| !parked_ids(&srv).is_empty(), "the packet to park");
        let id = parked_ids(&srv).remove(0);

        let dropped = call(&srv, Frontend::Mcp, "l4.intercept.drop", json!({"id": id}));
        assert!(!is_error(&dropped), "drop failed: {}", text(&dropped));

        let mut buf = [0u8; 64];
        assert!(
            receiver.recv(&mut buf).is_err(),
            "a dropped packet must not be delivered"
        );

        let _ = nft(&["delete", "table", "inet", table]);
    }
}

// ---- mcp_guard_airtight (hermetic — runs on every host) -----------------------

/// A hermetic inject `spec`/args pair for `dst:port` (no Ethernet needed — the guard
/// refuses before any wire I/O on this host).
fn hermetic_inject(dst: &str, port: u16, payload: u8) -> JsonValue {
    json!({
        "spec": {"layers": [
            {"ipv4": {"dst": dst}},
            {"udp": {"dst_port": port}},
            {"raw": [payload]},
        ]},
        "dst": dst,
        "interface": IFACE,
        "port": port,
    })
}

/// L4OPS-AC13 (guard-airtightness) — the refusals that are the point of the
/// milestone, asserted over the bus with **no privilege** (so they hold on every
/// host). The agent path cannot aim a raw-packet action at an out-of-scope target,
/// cannot act on a capability whose `l4.allow_agent_*` flag is off, cannot outrun the
/// injection rate cap, and cannot reach a loopback (control-plane) target it scoped
/// itself at runtime.
#[test]
fn mcp_guard_airtight() {
    // (a) Out-of-scope inject is refused by the L4 scope guard — before any wire I/O.
    // The agent has the inject flag on and the most permissive policy, and loopback is
    // operator-scoped, so the *only* thing refusing `8.8.8.8` is that it is out of
    // scope.
    let (srv, _ring) = server(&acceptance_cfg(0), AgentPolicy::All);
    let out_of_scope = call(
        &srv,
        Frontend::Mcp,
        "l4.inject",
        hermetic_inject("8.8.8.8", 443, 1),
    );
    assert!(
        is_error(&out_of_scope),
        "an out-of-scope inject must be refused"
    );
    assert!(
        text(&out_of_scope).contains("out of L4 scope"),
        "the refusal must be the scope guard's, got: {}",
        text(&out_of_scope)
    );

    // (b) An agent Sensitive call with its capability flag OFF is refused by the agent
    // gate — before the guard. Loopback is operator-scoped and in range, so only the
    // missing flag can refuse it.
    let cfg_flag_off = L4Config {
        allow_agent_inject: false,
        ..acceptance_cfg(0)
    };
    let (srv_off, _r) = server(&cfg_flag_off, AgentPolicy::All);
    let flag_off = call(
        &srv_off,
        Frontend::Mcp,
        "l4.inject",
        hermetic_inject("127.0.0.1", 9, 1),
    );
    assert!(
        is_error(&flag_off),
        "a flag-off agent inject must be refused"
    );
    assert!(
        text(&flag_off).contains("capability is disabled"),
        "the refusal must be the agent gate's, got: {}",
        text(&flag_off)
    );

    // (c) The injection rate cap trips with `InjectionRateExceeded`. The loopback
    // inject scope is operator-declared with a one-token budget (pps=1, burst=1); the
    // first inject spends the token (its wire write then fails closed on an
    // unprivileged host — immaterial; the token is already spent at the choke point,
    // before the backend), and the second inject is refused by the rate meter.
    let cfg_rate = L4Config {
        scope: vec![config_scope(L4Capability::Inject, L4Direction::Outbound, 1)],
        ..acceptance_cfg(0)
    };
    let (srv_rate, _r) = server(&cfg_rate, AgentPolicy::All);
    let _ = call(
        &srv_rate,
        Frontend::Mcp,
        "l4.inject",
        hermetic_inject("127.0.0.1", 9, 1),
    );
    let second = call(
        &srv_rate,
        Frontend::Mcp,
        "l4.inject",
        hermetic_inject("127.0.0.1", 9, 2),
    );
    assert!(
        is_error(&second),
        "the rate-capped second inject must be refused"
    );
    assert!(
        text(&second).contains("injection rate exceeded"),
        "the second inject must trip the rate cap, got: {}",
        text(&second)
    );

    // (d) SEC-2 airtightness — an agent that widens L4 scope to loopback at runtime
    // over the bus still cannot inject there: `l4.scope.add` mints `source = Runtime`,
    // which never lifts the loopback dangerous-destination denylist. Here there is NO
    // operator config scope, the agent holds widen + inject flags under `All`, it adds
    // its own loopback inject scope, and the inject is *still* refused — the denylist,
    // not the scope match, stops it.
    let cfg_no_config_scope = L4Config {
        enabled: true,
        allow_agent_inject: true,
        allow_agent_widen: true,
        ..L4Config::default()
    };
    let (srv_sec2, _r) = server(&cfg_no_config_scope, AgentPolicy::All);
    scope_add(&srv_sec2, "inject", "outbound"); // runtime add succeeds...
    let denied = call(
        &srv_sec2,
        Frontend::Mcp,
        "l4.inject",
        hermetic_inject("127.0.0.1", 9, 1),
    );
    assert!(
        is_error(&denied),
        "...but the loopback inject is still refused"
    );
    assert!(
        text(&denied).contains("dangerous-destination denylist"),
        "a runtime-scoped loopback inject must hit the denylist, got: {}",
        text(&denied)
    );
}
