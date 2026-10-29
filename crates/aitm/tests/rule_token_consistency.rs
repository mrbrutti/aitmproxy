//! Panel finding #3: the rule wire-serde (parse+echo and the phase/ws_dir/url/host
//! token tables) is now lifted into `aitm_rules::bus` and shared by `flow.intercept`
//! (F3), `ws.intercept` (F9) and `map.*` (Map Local/Remote). Before, the three
//! surfaces hand-rolled it and had drifted — `Phase::WsFrame` serialized as
//! `"wsframe"` in intercept but `"ws_frame"` in wsctl/maprules. This test pins the
//! canonical token and proves all three now emit (and accept) the same one.

use std::collections::BTreeMap;
use std::sync::Arc;

use aitm_core::{
    CommandHost, Frontend, HttpFlow, HttpRequest, MemFlowStore, Params, ProxyClient, Registry,
    ScopeRateGuard, StdGuard, Value,
};
use aitm_plugin_maprules::MapRulesPlugin;
use aitm_plugin_wsctl::WsCtlPlugin;
use aitm_plugins::InterceptPlugin;
use futures::future::BoxFuture;

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

fn obj(pairs: &[(&str, Value)]) -> Value {
    Value::Object(
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
    )
}

/// Invoke `command` with `args` as the operator (CLI) and return its result value.
fn invoke(reg: &Registry, store: &MemFlowStore, command: &str, args: Params) -> Value {
    let client = UnusedClient;
    let guard = StdGuard::default();
    let host = CommandHost::new(store, &client, &guard, None).with_frontend(Frontend::Cli);
    reg.command(command)
        .unwrap_or_else(|| panic!("{command} registered"))
        .invoke(args, &host)
        .unwrap_or_else(|e| panic!("{command} invoke: {e:#}"))
}

/// The `phase` string of the first rule echoed by `flow.intercept` / `ws.intercept`.
fn first_rule_phase(result: &Value) -> String {
    let Value::Object(o) = result else {
        panic!("result is an object");
    };
    let Some(Value::Array(rules)) = o.get("rules") else {
        panic!("result has a rules array");
    };
    let Value::Object(rule) = rules.first().expect("one rule") else {
        panic!("rule is an object");
    };
    let Some(Value::Str(phase)) = rule.get("phase") else {
        panic!("rule has a phase string");
    };
    phase.clone()
}

#[test]
fn ws_frame_token_is_consistent_across_rule_surfaces() {
    // flow.intercept (F3) — fed the canonical token, echoes it back.
    let mut intercept = Registry::new();
    intercept.add_plugin(Box::new(InterceptPlugin::new()));
    let store = MemFlowStore::new();
    let intercept_result = invoke(
        &intercept,
        &store,
        "flow.intercept",
        params(&[(
            "rules",
            Value::Array(vec![obj(&[("phase", Value::Str("ws_frame".into()))])]),
        )]),
    );
    let intercept_phase = first_rule_phase(&intercept_result);

    // flow.intercept also *accepts* the legacy `wsframe` spelling and normalizes it.
    let legacy = invoke(
        &intercept,
        &store,
        "flow.intercept",
        params(&[(
            "rules",
            Value::Array(vec![obj(&[("phase", Value::Str("wsframe".into()))])]),
        )]),
    );
    assert_eq!(
        first_rule_phase(&legacy),
        intercept_phase,
        "intercept normalizes the legacy `wsframe` spelling to the canonical token"
    );

    // ws.intercept (F9).
    let mut wsctl = Registry::new();
    wsctl.add_plugin(Box::new(WsCtlPlugin::new()));
    let ws_store = MemFlowStore::new();
    let ws_result = invoke(
        &wsctl,
        &ws_store,
        "ws.intercept",
        params(&[(
            "rules",
            Value::Array(vec![obj(&[("phase", Value::Str("ws_frame".into()))])]),
        )]),
    );
    let ws_phase = first_rule_phase(&ws_result);

    // map.* (Map Remote) — add a ws_frame-phase rule, then read it back from map.list.
    let guard: Arc<dyn ScopeRateGuard> = Arc::new(StdGuard::default());
    let mut maprules = Registry::new();
    maprules.add_plugin(Box::new(MapRulesPlugin::new(
        std::env::temp_dir(),
        true,
        guard,
    )));
    let map_store = MemFlowStore::new();
    invoke(
        &maprules,
        &map_store,
        "map.add",
        params(&[
            ("kind", Value::Str("remote".into())),
            (
                "condition",
                obj(&[
                    ("phase", Value::Str("ws_frame".into())),
                    ("host", obj(&[("exact", Value::Str("x.test".into()))])),
                ]),
            ),
            (
                "action",
                obj(&[("to", obj(&[("authority", Value::Str("y.test".into()))]))]),
            ),
        ]),
    );
    let listed = invoke(&maprules, &map_store, "map.list", params(&[]));
    let map_phase = {
        let Value::Object(o) = &listed else {
            panic!("map.list is an object");
        };
        let Some(Value::Array(maps)) = o.get("maps") else {
            panic!("map.list has a maps array");
        };
        let Value::Object(m) = maps.first().expect("one map") else {
            panic!("map is an object");
        };
        let Some(Value::Object(cond)) = m.get("condition") else {
            panic!("map has a condition object");
        };
        let Some(Value::Str(phase)) = cond.get("phase") else {
            panic!("condition has a phase string");
        };
        phase.clone()
    };

    // The canonical token, emitted identically by all three surfaces.
    assert_eq!(intercept_phase, "ws_frame", "intercept emits ws_frame");
    assert_eq!(ws_phase, "ws_frame", "ws.intercept emits ws_frame");
    assert_eq!(map_phase, "ws_frame", "map.list emits ws_frame");
    assert_eq!(intercept_phase, ws_phase);
    assert_eq!(ws_phase, map_phase);
}
