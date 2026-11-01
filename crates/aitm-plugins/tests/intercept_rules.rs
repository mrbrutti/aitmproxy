//! Task 3 (F3): selective, rule-based request-phase interception.
//!
//! `flow.intercept` gains an optional `rules` param. With no rules it keeps
//! today's global arm (park every request); with rules it parks only a request
//! that matches a rule at `Phase::Request`. A rule carrying an invalid regex
//! makes `invoke` return `Err`.
//!
//! Events are driven the way `Chain::dispatch` drives them (mirrors
//! `tests/intercept.rs`): the plugin's `on_event` runs over a `FlowCtx`, the
//! edited flow is persisted, and the parked receiver stands in for the chain's
//! pausable future.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::SystemTime;

use aitm_core::{
    Body, CommandHost, ConnInfo, Event, Flow, FlowCtx, FlowId, FlowMeta, FlowStore, HeaderMap,
    HttpFlow, HttpRequest, HttpVersion, InterceptState, MemFlowStore, Params, ProxyClient,
    Registry, StdGuard, Value, Verdict,
};
use aitm_plugins::InterceptPlugin;
use futures::future::BoxFuture;
use tokio::sync::oneshot;

fn http_flow(path: &str) -> Flow {
    http_flow_at("ex.test", path)
}

/// A `GET http://{authority}{path}` flow, for rules that name a host.
fn http_flow_at(authority: &str, path: &str) -> Flow {
    Flow::Http(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "GET".into(),
            scheme: "http".into(),
            authority: authority.into(),
            path: path.into(),
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            body: Body::Empty,
            timestamp: SystemTime::now(),
        },
        response: None,
        client_conn: ConnInfo {
            peer: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            sni: None,
            alpn: None,
            tls: false,
            established: SystemTime::now(),
        },
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    })
}

struct StubClient;

impl ProxyClient for StubClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("stub client") })
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

/// One rule object as it crosses the bus (a `flow.intercept {rules:[..]}` entry).
fn rule_obj(pairs: &[(&str, Value)]) -> Value {
    Value::Object(
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
    )
}

fn registry() -> Registry {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(InterceptPlugin::new()));
    reg
}

/// Run `Request(id)` through the registry's plugin chain as `Chain::dispatch`
/// does, persist the flow, and return the parked receiver if any plugin parked it.
fn dispatch_request(
    reg: &Registry,
    store: &MemFlowStore,
    id: FlowId,
) -> Option<oneshot::Receiver<()>> {
    let mut flow = store.get(id).expect("flow stored");
    let parked = {
        let mut ctx = FlowCtx::new(&mut flow);
        for plugin in reg.plugins() {
            let verdict = plugin
                .lock()
                .expect("plugin lock")
                .on_event(&Event::Request(id), &mut ctx);
            assert_eq!(verdict, Verdict::Continue);
        }
        ctx.take_parked()
    };
    store.insert(flow);
    parked
}

fn is_intercepted(store: &MemFlowStore, id: FlowId) -> bool {
    match store.get(id) {
        Some(Flow::Http(f)) => matches!(f.intercept, InterceptState::Intercepted { .. }),
        other => panic!("expected a stored HTTP flow, got {other:?}"),
    }
}

/// Arm `flow.intercept` with the given args and return its result value.
fn arm(reg: &Registry, host: &CommandHost, args: Params) -> Value {
    reg.command("flow.intercept")
        .expect("flow.intercept registered")
        .invoke(args, host)
        .expect("arming succeeds")
}

/// AC-F3.1: a request matching a request-phase rule parks.
#[test]
fn matching_request_parks() {
    let reg = registry();
    let store = MemFlowStore::new();
    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);

    let out = arm(
        &reg,
        &host,
        params(&[
            ("enabled", Value::Bool(true)),
            (
                "rules",
                Value::Array(vec![rule_obj(&[
                    ("url", Value::Str("*/admin".into())),
                    ("phase", Value::Str("request".into())),
                ])]),
            ),
        ]),
    );
    // The surface now returns an object, not a bare bool.
    match out {
        Value::Object(o) => assert_eq!(o.get("enabled"), Some(&Value::Bool(true))),
        other => panic!("flow.intercept should return an object, got {other:?}"),
    }

    let id = store.insert(http_flow("/admin"));
    let mut parked = dispatch_request(&reg, &store, id).expect("a matching request parks");
    assert!(
        is_intercepted(&store, id),
        "the matching flow is intercepted"
    );
    assert!(parked.try_recv().is_err(), "still parked before resume");
}

/// AC-F3.1 / RF#2: a concurrent non-matching request is never parked.
#[test]
fn non_matching_flow_not_parked() {
    let reg = registry();
    let store = MemFlowStore::new();
    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);

    arm(
        &reg,
        &host,
        params(&[
            ("enabled", Value::Bool(true)),
            (
                "rules",
                Value::Array(vec![rule_obj(&[
                    ("url", Value::Str("*/admin".into())),
                    ("phase", Value::Str("request".into())),
                ])]),
            ),
        ]),
    );

    // Matching sibling parks; the non-matching one sails through.
    let admin = store.insert(http_flow("/admin"));
    assert!(dispatch_request(&reg, &store, admin).is_some());

    let public = store.insert(http_flow("/public"));
    assert!(
        dispatch_request(&reg, &store, public).is_none(),
        "a non-matching request is not parked"
    );
    assert!(
        !is_intercepted(&store, public),
        "the non-matching flow is not intercepted"
    );
}

/// Back-compat: arming with no rules parks every request (today's behaviour).
#[test]
fn global_arm_still_parks_all() {
    let reg = registry();
    let store = MemFlowStore::new();
    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);

    arm(&reg, &host, params(&[("enabled", Value::Bool(true))]));

    for path in ["/admin", "/public", "/"] {
        let id = store.insert(http_flow(path));
        assert!(
            dispatch_request(&reg, &store, id).is_some(),
            "global arm parks {path}"
        );
        assert!(is_intercepted(&store, id));
    }
}

/// An invalid regex in a rule makes `invoke` return `Err`, and leaves the
/// previously-armed rules untouched.
#[test]
fn invalid_rule_regex_is_error() {
    let reg = registry();
    let store = MemFlowStore::new();
    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);

    // Arm with a valid rule first.
    arm(
        &reg,
        &host,
        params(&[
            ("enabled", Value::Bool(true)),
            (
                "rules",
                Value::Array(vec![rule_obj(&[
                    ("url", Value::Str("*/admin".into())),
                    ("phase", Value::Str("request".into())),
                ])]),
            ),
        ]),
    );

    // A bad regex rule is rejected without clobbering the active rules.
    let err = reg
        .command("flow.intercept")
        .expect("flow.intercept registered")
        .invoke(
            params(&[(
                "rules",
                Value::Array(vec![rule_obj(&[
                    ("url", rule_obj(&[("regex", Value::Str("[bad".into()))])),
                    ("phase", Value::Str("request".into())),
                ])]),
            )]),
            &host,
        )
        .expect_err("an invalid regex is rejected");
    assert!(
        err.to_string().to_lowercase().contains("regex"),
        "error should name the bad regex: {err}"
    );

    // The earlier `*/admin` rule is still active.
    let id = store.insert(http_flow("/admin"));
    assert!(
        dispatch_request(&reg, &store, id).is_some(),
        "the valid rule survived the failed call"
    );
}

/// AC12 (rule `url` clause matches the full request URL): a `url` wildcard that
/// names a host parks the flow for that host, and a flow to another host with
/// the same path sails through. Before the full-URL subject the clause ran
/// against the path only, so `*ex.test*` could never fire.
#[test]
fn host_bearing_rule_parks_matching_host() {
    let reg = registry();
    let store = MemFlowStore::new();
    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);

    arm(
        &reg,
        &host,
        params(&[
            ("enabled", Value::Bool(true)),
            (
                "rules",
                Value::Array(vec![rule_obj(&[
                    ("url", Value::Str("*ex.test*".into())),
                    ("phase", Value::Str("request".into())),
                ])]),
            ),
        ]),
    );

    let matching = store.insert(http_flow_at("ex.test", "/anything"));
    let mut parked = dispatch_request(&reg, &store, matching)
        .expect("a host-bearing url rule parks the flow for that host");
    assert!(
        is_intercepted(&store, matching),
        "GET http://ex.test/anything is intercepted under *ex.test*"
    );
    assert!(parked.try_recv().is_err(), "still parked before resume");

    let other = store.insert(http_flow_at("other.test", "/anything"));
    assert!(
        dispatch_request(&reg, &store, other).is_none(),
        "GET http://other.test/anything is not parked under *ex.test*"
    );
    assert!(
        !is_intercepted(&store, other),
        "the other host's flow stays observed"
    );
}

/// AC18: more than 256 rules in one call is rejected before any is compiled,
/// naming the cap, and the previously armed rule stays active; 256 is accepted.
#[test]
fn too_many_rules_is_error() {
    let reg = registry();
    let store = MemFlowStore::new();
    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);

    arm(
        &reg,
        &host,
        params(&[
            ("enabled", Value::Bool(true)),
            (
                "rules",
                Value::Array(vec![rule_obj(&[
                    ("url", Value::Str("*/admin".into())),
                    ("phase", Value::Str("request".into())),
                ])]),
            ),
        ]),
    );

    let rules = |n: usize| {
        Value::Array(
            (0..n)
                .map(|_| rule_obj(&[("url", Value::Str("*/x*".into()))]))
                .collect(),
        )
    };
    let intercept = reg
        .command("flow.intercept")
        .expect("flow.intercept registered");

    let err = intercept
        .invoke(params(&[("rules", rules(257))]), &host)
        .expect_err("257 rules are rejected");
    assert!(
        err.to_string().contains("limit is 256"),
        "the error names the cap: {err}"
    );

    // The earlier `*/admin` rule is still active.
    let id = store.insert(http_flow("/admin"));
    assert!(
        dispatch_request(&reg, &store, id).is_some(),
        "the valid rule survived the rejected call"
    );

    let out = intercept
        .invoke(params(&[("rules", rules(256))]), &host)
        .expect("256 rules is the cap, inclusive");
    match out {
        Value::Object(o) => match o.get("rules") {
            Some(Value::Array(active)) => assert_eq!(active.len(), 256),
            other => panic!("flow.intercept should echo the rules array, got {other:?}"),
        },
        other => panic!("flow.intercept should return an object, got {other:?}"),
    }
}

/// The `rules` param description (what `tools/list` shows an agent or operator
/// before they call) names every cause that rejects the whole call, not only
/// the invalid regex: the 256-rule cap, the 4096-byte pattern cap and the empty
/// pattern, and says the active rules survive the rejection. The MCP layer
/// copies the string verbatim (`rule_schemas_state_the_full_url_subject` in
/// `crates/aitm/tests/intercept_url_rules_mcp.rs` shows that for `rules[].url`),
/// so the pin lives at the schema.
#[test]
fn rules_param_text_names_every_rejection_cause() {
    let reg = registry();
    let schema = reg
        .command("flow.intercept")
        .expect("flow.intercept registered")
        .schema();
    let rules = schema
        .params
        .iter()
        .find(|p| p.name == "rules")
        .unwrap_or_else(|| {
            let names: Vec<&str> = schema.params.iter().map(|p| p.name.as_str()).collect();
            panic!("flow.intercept has a `rules` param; got {names:?}")
        });
    for phrase in [
        "256",
        "4096",
        "empty url pattern",
        "invalid regex",
        "unchanged",
    ] {
        assert!(
            rules.description.contains(phrase),
            "the flow.intercept `rules` description must name `{phrase}`; got: {}",
            rules.description
        );
    }
}

/// AC19 at the plugin level: an empty `url` pattern in any of its three bus
/// spellings (`""`, `{wildcard: ""}`, `{regex: ""}`) makes `flow.intercept`
/// return `Err` naming the empty pattern, and the previously armed rule stays
/// active instead of being replaced by a match-everything rule.
#[test]
fn empty_url_pattern_is_error() {
    let reg = registry();
    let store = MemFlowStore::new();
    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);

    arm(
        &reg,
        &host,
        params(&[
            ("enabled", Value::Bool(true)),
            (
                "rules",
                Value::Array(vec![rule_obj(&[
                    ("url", Value::Str("*/admin".into())),
                    ("phase", Value::Str("request".into())),
                ])]),
            ),
        ]),
    );
    let intercept = reg
        .command("flow.intercept")
        .expect("flow.intercept registered");

    for (what, url) in [
        ("bare string", Value::Str(String::new())),
        (
            "{wildcard}",
            rule_obj(&[("wildcard", Value::Str(String::new()))]),
        ),
        ("{regex}", rule_obj(&[("regex", Value::Str(String::new()))])),
    ] {
        let err = intercept
            .invoke(
                params(&[("rules", Value::Array(vec![rule_obj(&[("url", url)])]))]),
                &host,
            )
            .expect_err(what);
        assert!(
            err.to_string().contains("empty url pattern"),
            "{what}: the error should name the empty pattern: {err}"
        );
    }

    // The earlier `*/admin` rule is still active, and nothing else parks.
    let admin = store.insert(http_flow("/admin"));
    assert!(
        dispatch_request(&reg, &store, admin).is_some(),
        "the valid rule survived the rejected calls"
    );
    let public = store.insert(http_flow("/public"));
    assert!(
        dispatch_request(&reg, &store, public).is_none(),
        "no match-everything rule was armed by the rejected calls"
    );
}
