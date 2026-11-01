//! M6 Task 14 — the whole-branch assembly.
//!
//! The binary wiring converges five additive features: every new first-party
//! command is registered into the one `Registry` the frontends share; the
//! `PassthroughModule` is ordered before `HttpModule` so a pinned SNI tunnels
//! past MITM; the additive `Config.tls`/`Config.maps` sections parse with
//! `deny_unknown_fields`; and the agent gates default to the deny-by-default
//! posture (off) with no config overrides.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use aitm::config_file::parse;
use aitm::wire::{assemble, ordered_modules};
use aitm_core::{
    CommandHost, Config, Frontend, HttpFlow, HttpRequest, NextLayerHint, Params, ProxyClient, Value,
};
use aitm_plugin_passthrough::PassthroughList;
use aitm_proto_http::{CertAuthority, HttpModule};
use aitm_proto_ws::InjectRegistry;
use futures::future::BoxFuture;

fn temp_ca_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("aitm-m6-wire-{tag}-{nanos}-{n}"))
}

fn config(tag: &str) -> Config {
    let mut cfg = Config::default();
    cfg.ca.dir = temp_ca_dir(tag);
    cfg
}

/// A `ProxyClient` the gate checks never reach (the agent refusal precedes any
/// upstream call).
struct UnusedClient;

impl ProxyClient for UnusedClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("not called") })
    }
}

fn params(pairs: &[(&str, Value)]) -> Params {
    Params::new(
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
    )
}

/// Every M6 command the five features add is present in the assembled registry —
/// the `tools/list` a frontend enumerates. (`flow.intercept`/`flow.mutate`/
/// `flow.kill` are F3 extensions of the existing intercept/mutate plugins.)
#[test]
fn assembles_with_all_m6_plugins() {
    let cfg = config("plugins");
    let proxy = assemble(&cfg).expect("assemble").proxy;
    let reg = proxy.registry();
    for name in [
        "flow.intercept",
        "flow.mutate",
        "flow.kill",
        "ws.send",
        "ws.intercept",
        "ws.frame",
        "session.save",
        "session.load",
        "flow.export",
        "flow.import",
        "tls.passthrough.add",
        "map.add",
    ] {
        assert!(
            reg.command(name).is_some(),
            "{name} must be registered by assemble()"
        );
    }
}

/// `PassthroughModule` is registered before `HttpModule`, so the acceptor (which
/// picks the first module whose `matches` returns true) selects passthrough for a
/// pinned SNI even though `HttpModule` would also claim a TLS connection.
#[test]
fn passthrough_module_ordered_before_http() {
    let dir = temp_ca_dir("order");
    let ca = Arc::new(CertAuthority::load_or_generate(&dir, 0o600).expect("ca"));
    let http = HttpModule::with_ca(ca);
    let list = PassthroughList::new(vec!["pinned.example".into()]);
    let modules = ordered_modules(http, list, InjectRegistry::default());

    assert_eq!(
        modules[0].id(),
        "passthrough",
        "passthrough must be the first module so its match wins"
    );

    let dst: SocketAddr = "203.0.113.1:443".parse().unwrap();
    let pinned = NextLayerHint {
        dst,
        is_tls: true,
        client_hello_sni: Some("pinned.example".into()),
        alpn: Vec::new(),
        first_bytes: vec![0x16],
        from_upgrade: false,
        peer_identity: None,
        capture_interface: None,
    };
    let chosen = modules
        .iter()
        .find(|m| m.matches(&pinned))
        .expect("a module claims the pinned-SNI connection");
    assert_eq!(chosen.id(), "passthrough");

    // A non-pinned TLS connection still goes to HTTP (MITM), not passthrough.
    let other = NextLayerHint {
        client_hello_sni: Some("other.example".into()),
        ..pinned
    };
    let chosen = modules
        .iter()
        .find(|m| m.matches(&other))
        .expect("a module claims the ordinary connection");
    assert_eq!(chosen.id(), "http");
}

/// The additive `tls:` section parses, and an unknown key under it is an error
/// (`deny_unknown_fields`). Omitting `tls`/`maps` leaves the deny-by-default
/// posture.
#[test]
fn config_rejects_unknown_tls_key() {
    // Omitted → defaults: empty passthrough, agent gates off, no map root.
    let cfg = parse("listen: 127.0.0.1:8080\n").expect("minimal config parses");
    assert!(cfg.tls.passthrough.is_empty());
    assert!(!cfg.tls.allow_agent_passthrough);
    assert!(cfg.maps.root.is_none());
    assert!(!cfg.maps.allow_agent_authoring);

    // A well-formed tls section applies.
    let cfg = parse(
        "tls:\n  passthrough: [\"pinned.example\"]\n  allow_agent_passthrough: true\nmaps:\n  allow_agent_authoring: true\n",
    )
    .expect("tls/maps sections parse");
    assert_eq!(cfg.tls.passthrough, vec!["pinned.example".to_string()]);
    assert!(cfg.tls.allow_agent_passthrough);
    assert!(cfg.maps.allow_agent_authoring);

    // An unknown key under tls is refused, not silently kept as a default.
    let err =
        parse("tls:\n  passthru: [\"typo.example\"]\n").expect_err("unknown tls key is rejected");
    // The whole cause chain (`{:#}`) carries serde's "unknown field" message.
    let chain = format!("{err:#}").to_lowercase();
    assert!(
        chain.contains("passthru") || chain.contains("unknown field"),
        "the error names the bad key: {chain}"
    );
}

/// With no config overrides, the agent (MCP) gates on the behaviour-changing
/// commands default **off**: both `tls.passthrough.add` and `map.add` from
/// `Frontend::Mcp` are refused.
#[test]
fn agent_gates_default_off() {
    let cfg = config("gates");
    let proxy = assemble(&cfg).expect("assemble").proxy;
    let reg = proxy.registry();

    let store = proxy.store();
    let guard = proxy.guard();
    let client = UnusedClient;
    let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), None)
        .with_frontend(Frontend::Mcp);

    let err = reg
        .command("tls.passthrough.add")
        .expect("tls.passthrough.add registered")
        .invoke(
            params(&[("host", Value::Str("pinned.example".into()))]),
            &host,
        )
        .expect_err("agent passthrough add is refused by default");
    assert!(
        err.to_string().to_lowercase().contains("refus")
            || err.to_string().to_lowercase().contains("agent"),
        "the refusal is explained: {err}"
    );

    // The agent gate fires before any argument is read, so a minimal call is
    // enough to observe the default-off refusal.
    let err = reg
        .command("map.add")
        .expect("map.add registered")
        .invoke(Params::default(), &host)
        .expect_err("agent map authoring is refused by default");
    assert!(
        err.to_string().to_lowercase().contains("refus")
            || err.to_string().to_lowercase().contains("agent"),
        "the refusal is explained: {err}"
    );
}
