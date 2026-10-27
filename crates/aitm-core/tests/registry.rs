//! Task 4: the command registry, typed params/values, and the option API.

use aitm_core::{
    Command, CommandHost, HttpFlow, HttpRequest, MemFlowStore, ParamSchema, Params, ProxyClient,
    Registry, StdGuard, TypeDesc, Value,
};
use futures::future::BoxFuture;
use std::collections::BTreeMap;
use std::sync::Arc;

/// A trivial command that ignores its arguments and host.
struct PingCmd;

impl Command for PingCmd {
    fn name(&self) -> &str {
        "demo.ping"
    }
    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "ping".into(),
            params: vec![],
            result: TypeDesc::Str,
        }
    }
    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        Ok(Value::Str("pong".into()))
    }
}

/// A `ProxyClient` stub: the Task 4 host needs one, but `demo.ping` never calls it.
struct StubClient;

impl ProxyClient for StubClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

#[test]
fn register_and_lookup_command() {
    let mut reg = Registry::new();
    reg.add_command(Arc::new(PingCmd));
    assert!(reg.command("demo.ping").is_some());

    let store = MemFlowStore::new();
    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);

    let cmd = reg.command("demo.ping").expect("registered").clone();
    let out = cmd.invoke(Params::default(), &host).expect("invoke ok");
    assert_eq!(out, Value::Str("pong".into()));
}

#[test]
fn option_roundtrip() {
    let mut reg = Registry::new();
    reg.add_option("tag", Value::Str("x".into()), "a tag applied to flows");
    assert_eq!(reg.option("tag"), Some(Value::Str("x".into())));
}

#[test]
fn params_typed_get() {
    let mut map = BTreeMap::new();
    map.insert("id".to_string(), Value::Str("u".into()));
    let params = Params::new(map);
    assert_eq!(params.get_str("id").expect("present and a string"), "u");
}
