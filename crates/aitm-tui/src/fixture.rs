//! A bus made of recorded data. [`FixtureTransport`] speaks the same
//! newline-delimited JSON-RPC as the proxy's MCP server, so the whole UI runs
//! unchanged against `fixtures/bus-fixture.json` when no proxy is up
//! (`aitm-tui --fixture`), and the screens can be tested deterministically.
//! Mutating commands update the in-memory fixture the way the core would:
//! resume attaches the recorded `on_resume` response, kill marks the flow,
//! replay and `request.send` append flows.

use std::sync::{Arc, Mutex};

use aitm_bus_client::{BoxFuture, BusTransport};
use serde_json::{json, Map, Value};

use crate::base64;

/// The fixture that ships with the crate.
pub const BUILTIN: &str = include_str!("../fixtures/bus-fixture.json");

/// Shared fixture state; every connection to it sees the same flows.
pub type Shared = Arc<Mutex<Fixture>>;

/// The recorded bus.
#[derive(Debug, Clone)]
pub struct Fixture {
    pub server_name: String,
    pub server_version: String,
    pub listening: String,
    pub intercept_armed: bool,
    pub capture_paused: bool,
    pub scope: Vec<String>,
    pub agent: Value,
    pub tools: Vec<Value>,
    pub flows: Vec<Value>,
    pub findings: Vec<Value>,
    next_id: u64,
}

impl Fixture {
    /// Parse a fixture document.
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let v: Value = serde_json::from_str(text)?;
        let arr = |k: &str| -> Vec<Value> {
            v.get(k)
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        };
        let flows = arr("flows");
        let next_id = flows
            .iter()
            .filter_map(|f| {
                f.get("id")?
                    .as_str()?
                    .trim_start_matches('f')
                    .parse::<u64>()
                    .ok()
            })
            .max()
            .unwrap_or(0)
            + 1;
        Ok(Self {
            server_name: v
                .pointer("/server/name")
                .and_then(Value::as_str)
                .unwrap_or("aitmproxy")
                .to_string(),
            server_version: v
                .pointer("/server/version")
                .and_then(Value::as_str)
                .unwrap_or("fixture")
                .to_string(),
            listening: v
                .get("listening")
                .and_then(Value::as_str)
                .unwrap_or("127.0.0.1:8080")
                .to_string(),
            intercept_armed: v
                .get("intercept_armed")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            capture_paused: v
                .get("capture_paused")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            scope: arr("scope")
                .iter()
                .filter_map(|s| s.as_str().map(str::to_string))
                .collect(),
            agent: v
                .get("agent")
                .cloned()
                .unwrap_or_else(|| json!({"policy":"all"})),
            tools: arr("tools"),
            flows,
            findings: arr("findings"),
            next_id,
        })
    }

    /// The fixture shipped with the crate.
    pub fn builtin() -> Self {
        Self::parse(BUILTIN).unwrap_or_else(|e| panic!("built-in fixture is invalid: {e}"))
    }

    pub fn shared(self) -> Shared {
        Arc::new(Mutex::new(self))
    }

    fn flow_mut(&mut self, id: &str) -> Result<&mut Value, String> {
        self.flows
            .iter_mut()
            .find(|f| f.get("id").and_then(Value::as_str) == Some(id))
            .ok_or_else(|| format!("no flow with id {id}"))
    }

    fn flow(&self, id: &str) -> Result<&Value, String> {
        self.flows
            .iter()
            .find(|f| f.get("id").and_then(Value::as_str) == Some(id))
            .ok_or_else(|| format!("no flow with id {id}"))
    }

    /// The `flow.get` summary of a stored flow.
    fn summary(f: &Value) -> Value {
        let mut o = Map::new();
        o.insert("id".into(), f["id"].clone());
        let kind = f.get("kind").and_then(Value::as_str).unwrap_or("http");
        o.insert("kind".into(), Value::String(kind.into()));
        o.insert(
            "intercept".into(),
            f.get("intercept")
                .cloned()
                .unwrap_or(Value::String("observed".into())),
        );
        o.insert(
            "is_replay".into(),
            f.pointer("/meta/is_replay")
                .cloned()
                .unwrap_or(Value::Bool(false)),
        );
        if kind == "websocket" {
            o.insert(
                "handshake".into(),
                f.get("handshake").cloned().unwrap_or(Value::Null),
            );
            o.insert(
                "messages".into(),
                Value::from(
                    f.get("frames")
                        .and_then(Value::as_array)
                        .map_or(0, Vec::len),
                ),
            );
        } else {
            for k in ["method", "scheme", "authority", "path"] {
                o.insert(
                    k.into(),
                    f.pointer(&format!("/request/{k}"))
                        .cloned()
                        .unwrap_or(Value::Null),
                );
            }
            o.insert(
                "status".into(),
                f.pointer("/response/status")
                    .cloned()
                    .unwrap_or(Value::Null),
            );
        }
        Value::Object(o)
    }

    /// The `flow.detail` view: bodies and frames as base64.
    fn detail(f: &Value) -> Value {
        let mut d = f.clone();
        if let Some(obj) = d.as_object_mut() {
            obj.remove("on_resume");
            for side in ["request", "response"] {
                if let Some(m) = obj.get_mut(side).and_then(Value::as_object_mut) {
                    encode_body(m);
                }
            }
            if let Some(frames) = obj.get_mut("frames").and_then(Value::as_array_mut) {
                for fr in frames.iter_mut().filter_map(Value::as_object_mut) {
                    if let Some(Value::String(t)) = fr.remove("data_text") {
                        fr.insert("data".into(), Value::String(base64::encode(t.as_bytes())));
                    }
                }
            }
        }
        d
    }

    fn new_id(&mut self) -> String {
        let id = format!("f{}", self.next_id);
        self.next_id += 1;
        id
    }

    /// Run one tool. `Err` is a tool error (`isError: true`).
    pub fn call(&mut self, name: &str, args: &Map<String, Value>) -> Result<Value, String> {
        let id_arg = || -> Result<String, String> {
            args.get("id")
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| "missing `id`".to_string())
        };
        match name {
            "flow.list" => Ok(Value::Array(
                self.flows.iter().map(|f| f["id"].clone()).collect(),
            )),
            "flow.get" => Ok(Self::summary(self.flow(&id_arg()?)?)),
            "flow.detail" => Ok(Self::detail(self.flow(&id_arg()?)?)),
            "flow.intercept" => {
                self.intercept_armed = args.get("enabled").and_then(Value::as_bool).unwrap_or(true);
                Ok(Value::Bool(self.intercept_armed))
            }
            "flow.resume" => {
                let f = self.flow_mut(&id_arg()?)?;
                if f.get("intercept").and_then(Value::as_str) != Some("intercepted") {
                    return Err("flow is not intercepted".into());
                }
                f["intercept"] = Value::String("resumed".into());
                let resp = f
                    .as_object_mut()
                    .and_then(|o| o.remove("on_resume"))
                    .unwrap_or_else(
                        || json!({"status":200,"version":"HTTP/1.1","headers":[],"body_text":""}),
                    );
                f["response"] = resp;
                if f["meta"]["duration_ms"].is_null() {
                    f["meta"]["duration_ms"] = Value::from(240);
                }
                Ok(Value::String("ok".into()))
            }
            "flow.kill" => {
                let f = self.flow_mut(&id_arg()?)?;
                f["intercept"] = Value::String("killed".into());
                Ok(Value::String("ok".into()))
            }
            "flow.mutate" => {
                let id = id_arg()?;
                let edits = args
                    .get("edits")
                    .and_then(Value::as_object)
                    .cloned()
                    .ok_or_else(|| "missing `edits`".to_string())?;
                let f = self.flow_mut(&id)?;
                let req = f
                    .get_mut("request")
                    .and_then(Value::as_object_mut)
                    .ok_or_else(|| "flow has no request".to_string())?;
                for (k, v) in edits {
                    match k.as_str() {
                        "method" | "path" | "scheme" | "authority" => {
                            req.insert(k, v);
                        }
                        "headers" => {
                            let mut headers: Vec<Value> = req
                                .get("headers")
                                .and_then(Value::as_array)
                                .cloned()
                                .unwrap_or_default();
                            for (hn, hv) in v.as_object().cloned().unwrap_or_default() {
                                headers.retain(|h| {
                                    h.get(0)
                                        .and_then(Value::as_str)
                                        .is_none_or(|n| !n.eq_ignore_ascii_case(&hn))
                                });
                                headers.push(json!([hn, hv]));
                            }
                            req.insert("headers".into(), Value::Array(headers));
                        }
                        "body" => {
                            req.remove("body");
                            req.insert("body_text".into(), v);
                        }
                        other => return Err(format!("unknown edit `{other}`")),
                    }
                }
                f["edited"] = Value::Bool(true);
                Ok(Value::String(id))
            }
            "flow.replay" => {
                let id = id_arg()?;
                let mut copy = self.flow(&id)?.clone();
                if copy.get("kind").and_then(Value::as_str) == Some("websocket") {
                    return Err("only HTTP flows can be replayed".into());
                }
                let new_id = self.new_id();
                copy["id"] = Value::String(new_id.clone());
                copy["intercept"] = Value::String("observed".into());
                copy["edited"] = Value::Bool(false);
                copy["meta"]["is_replay"] = Value::Bool(true);
                copy["meta"]["origin"] = Value::String("human".into());
                copy["meta"]["marks"] = json!([]);
                copy["meta"]["comment"] = Value::Null;
                if copy["response"].is_null() {
                    copy["response"] = json!({"status":200,"version":"HTTP/1.1","headers":[["content-type","application/json"]],"body_text":"{\"replayed\":true}"});
                }
                self.flows.push(copy);
                Ok(Value::String(new_id))
            }
            "request.send" => {
                let authority = args
                    .get("authority")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "missing `authority`".to_string())?
                    .to_string();
                if !crate::app::scope_covers(&self.scope, &authority) {
                    return Err(format!("{authority} is out of scope"));
                }
                let new_id = self.new_id();
                let headers: Vec<Value> = args
                    .get("headers")
                    .and_then(Value::as_object)
                    .map(|m| m.iter().map(|(k, v)| json!([k, v])).collect())
                    .unwrap_or_default();
                let body = args
                    .get("body")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                self.flows.push(json!({
                    "id": new_id, "kind": "http", "intercept": "observed", "edited": false,
                    "request": {
                        "method": args.get("method").and_then(Value::as_str).unwrap_or("GET"),
                        "scheme": args.get("scheme").and_then(Value::as_str).unwrap_or("https"),
                        "authority": authority, "path": args.get("path").and_then(Value::as_str).unwrap_or("/"),
                        "version": "HTTP/1.1", "headers": headers, "body_text": body },
                    "response": {"status": 200, "version": "HTTP/1.1", "headers": [["content-type","application/json"]], "body_text": "{\"ok\": true}"},
                    "client_conn": {"peer": "127.0.0.1:9", "tls": true, "process": "aitm"},
                    "meta": {"marks": [], "comment": null, "is_replay": true, "created": "2026-10-27T11:06:00.000Z", "duration_ms": 180, "truncated": false, "origin": "human"}
                }));
                Ok(Value::String(new_id))
            }
            "scope.list" => Ok(Value::Array(
                self.scope.iter().cloned().map(Value::String).collect(),
            )),
            "scope.add" => {
                let host = args
                    .get("host")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "missing `host`".to_string())?
                    .to_string();
                if !self.scope.contains(&host) {
                    self.scope.push(host.clone());
                }
                Ok(Value::String(host))
            }
            "scope.remove" => {
                let host = args.get("host").and_then(Value::as_str).unwrap_or("");
                self.scope.retain(|h| h != host);
                Ok(Value::String(host.to_string()))
            }
            "poc.build" => {
                let flow_id = args
                    .get("flow_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "missing `flow_id`".to_string())?;
                self.flow(flow_id)?;
                let name = args
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("poc")
                    .to_lowercase()
                    .replace(|c: char| !c.is_alphanumeric(), "-");
                Ok(Value::String(format!("pocs/{name}.yaml")))
            }
            "poc.run" => {
                let path = args
                    .get("poc_path")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "missing `poc_path`".to_string())?
                    .to_string();
                let capture = self
                    .flows
                    .first()
                    .map(|f| f["id"].clone())
                    .unwrap_or(Value::Null);
                let result = json!({
                    "passed": true, "finding_capture": capture, "poc_path": path,
                    "screenshot_path": path.replace(".yaml", ".png"),
                    "evaluated": [{"assertion": "status == 200", "matched": true}],
                    "severity": "info", "target": args.get("target").cloned().unwrap_or(Value::Null),
                    "at": "2026-10-27T11:07:00.000Z", "origin": "human"
                });
                self.findings.insert(0, result.clone());
                Ok(result)
            }
            "poc.list" => Ok(Value::Array(self.findings.clone())),
            "agent.status" => Ok(self.agent.clone()),
            "agent.set" => {
                let p = args
                    .get("policy")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "missing `policy`".to_string())?;
                if !matches!(p, "all" | "readonly" | "paused") {
                    return Err(format!("unknown policy `{p}`"));
                }
                self.agent["policy"] = Value::String(p.into());
                Ok(Value::String(p.into()))
            }
            "proxy.status" => Ok(
                json!({"listening": self.listening, "paused": self.capture_paused, "protocol": "HTTP/2"}),
            ),
            "proxy.pause" => {
                self.capture_paused = args.get("paused").and_then(Value::as_bool).unwrap_or(true);
                Ok(Value::Bool(self.capture_paused))
            }
            "flow.clear" => {
                let n = self.flows.len();
                self.flows.clear();
                Ok(Value::from(n))
            }
            "flow.mark" => {
                let f = self.flow_mut(&id_arg()?)?;
                f["meta"]["marks"] = args.get("marks").cloned().unwrap_or_else(|| json!([]));
                Ok(Value::String("ok".into()))
            }
            "flow.comment" => {
                let f = self.flow_mut(&id_arg()?)?;
                f["meta"]["comment"] = args.get("text").cloned().unwrap_or(Value::Null);
                Ok(Value::String("ok".into()))
            }
            "ca.status" => Ok(
                json!({"path": "~/.aitm/ca.crt", "fingerprint_sha256": "3A:F1:…:9C", "installed": false, "platform": "fixture"}),
            ),
            n if n.starts_with("browser.") => {
                Err("fixture has no browser engine; run against a live proxy".into())
            }
            n if n.starts_with("ca.") => Err("CA changes are not simulated by the fixture".into()),
            other => Err(format!("fixture does not implement `{other}`")),
        }
    }

    /// Handle one JSON-RPC line exactly as `McpServer::handle` would.
    pub fn handle(&mut self, line: &str) -> Option<String> {
        let req: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => return Some(rpc_error(Value::Null, -32700, format!("parse error: {e}"))),
        };
        let id = req.get("id").cloned();
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");
        let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
        let result = match method {
            "initialize" => Ok(json!({
                "protocolVersion": params.get("protocolVersion").cloned().unwrap_or(Value::String(aitm_bus_client::PROTOCOL_VERSION.into())),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": self.server_name, "version": self.server_version},
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": self.tools})),
            "tools/call" => {
                let name = params.get("name").and_then(Value::as_str).unwrap_or("");
                let empty = Map::new();
                let args = params
                    .get("arguments")
                    .and_then(Value::as_object)
                    .unwrap_or(&empty);
                if !self
                    .tools
                    .iter()
                    .any(|t| t.get("name").and_then(Value::as_str) == Some(name))
                {
                    Err((-32602, format!("unknown tool `{name}`")))
                } else {
                    Ok(match self.call(name, args) {
                        Ok(v) => {
                            json!({"content":[{"type":"text","text":v.to_string()}],"structuredContent":v,"isError":false})
                        }
                        Err(m) => json!({"content":[{"type":"text","text":m}],"isError":true}),
                    })
                }
            }
            m if m.starts_with("notifications/") => Ok(Value::Null),
            other => Err((-32601, format!("unknown method `{other}`"))),
        };
        let id = id?;
        Some(match result {
            Ok(r) => json!({"jsonrpc":"2.0","id":id,"result":r}).to_string(),
            Err((code, msg)) => rpc_error(id, code, msg),
        })
    }
}

fn encode_body(m: &mut Map<String, Value>) {
    if let Some(Value::String(t)) = m.remove("body_text") {
        m.insert("body".into(), Value::String(base64::encode(t.as_bytes())));
    } else if let Some(b) = m.remove("body_b64") {
        m.insert("body".into(), b);
    }
}

fn rpc_error(id: Value, code: i64, message: String) -> String {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}}).to_string()
}

/// A [`BusTransport`] over a shared [`Fixture`].
pub struct FixtureTransport {
    state: Shared,
}

impl FixtureTransport {
    pub fn new(state: Shared) -> Self {
        Self { state }
    }

    fn handle(&self, line: &str) -> Option<String> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .handle(line)
    }
}

impl BusTransport for FixtureTransport {
    fn send(&self, line: String) -> BoxFuture<'_, anyhow::Result<Option<String>>> {
        let reply = self.handle(&line);
        Box::pin(async move { Ok(reply) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitm_bus_client::{BusClient, BusError};

    fn client() -> (BusClient, Shared) {
        let shared = Fixture::builtin().shared();
        (
            BusClient::new(Box::new(FixtureTransport::new(shared.clone()))),
            shared,
        )
    }

    #[tokio::test]
    async fn builtin_fixture_round_trips_through_the_client() {
        let (c, _) = client();
        let info = c.initialize("test", "0").await.unwrap();
        assert_eq!(info.name, "aitmproxy");
        let tools = c.tools_list().await.unwrap();
        assert!(tools.iter().any(|t| t.name == "flow.detail"));
        let ids = c.call("flow.list", json!({})).await.unwrap();
        assert_eq!(ids.as_array().unwrap().len(), 14);
        let s = c.call("flow.get", json!({"id":"f50"})).await.unwrap();
        assert_eq!(s["method"], "POST");
        assert_eq!(s["intercept"], "intercepted");
        assert!(s["status"].is_null());
        let d = c.call("flow.detail", json!({"id":"f50"})).await.unwrap();
        let body = base64::decode(d["request"]["body"].as_str().unwrap()).unwrap();
        assert!(String::from_utf8(body)
            .unwrap()
            .contains("correct-horse-battery"));
        assert!(d.get("on_resume").is_none());
    }

    #[tokio::test]
    async fn resume_attaches_the_recorded_response_and_kill_marks() {
        let (c, _) = client();
        c.call("flow.resume", json!({"id":"f50"})).await.unwrap();
        let s = c.call("flow.get", json!({"id":"f50"})).await.unwrap();
        assert_eq!(s["status"], 200);
        assert_eq!(s["intercept"], "resumed");
        let err = c
            .call("flow.resume", json!({"id":"f41"}))
            .await
            .unwrap_err();
        assert!(matches!(err, BusError::Tool(m) if m == "flow is not intercepted"));
        c.call("flow.kill", json!({"id":"f51"})).await.unwrap();
        let s = c.call("flow.get", json!({"id":"f51"})).await.unwrap();
        assert_eq!(s["intercept"], "killed");
    }

    #[tokio::test]
    async fn mutate_replaces_headers_and_replay_appends_a_flow() {
        let (c, _) = client();
        c.call(
            "flow.mutate",
            json!({"id":"f50","edits":{"headers":{"X-Forwarded-For":"10.0.0.1"},"body":"{}"}}),
        )
        .await
        .unwrap();
        let d = c.call("flow.detail", json!({"id":"f50"})).await.unwrap();
        let headers = d["request"]["headers"].as_array().unwrap();
        let xff: Vec<&Value> = headers
            .iter()
            .filter(|h| {
                h[0].as_str()
                    .unwrap()
                    .eq_ignore_ascii_case("x-forwarded-for")
            })
            .collect();
        assert_eq!(xff.len(), 1);
        assert_eq!(xff[0][1], "10.0.0.1");
        assert_eq!(d["edited"], true);
        let new_id = c.call("flow.replay", json!({"id":"f45"})).await.unwrap();
        assert_eq!(new_id, "f55");
        let ids = c.call("flow.list", json!({})).await.unwrap();
        assert_eq!(ids.as_array().unwrap().len(), 15);
        let s = c.call("flow.get", json!({"id":"f55"})).await.unwrap();
        assert_eq!(s["is_replay"], true);
    }

    #[tokio::test]
    async fn request_send_is_scope_guarded_and_unknown_tools_are_rpc_errors() {
        let (c, _) = client();
        let err = c
            .call(
                "request.send",
                json!({"authority":"evil.example","path":"/"}),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, BusError::Tool(m) if m.contains("out of scope")));
        let id = c
            .call(
                "request.send",
                json!({"authority":"api.shop-staging.test","path":"/x","method":"POST"}),
            )
            .await
            .unwrap();
        assert_eq!(id, "f55");
        let err = c.call("nope", json!({})).await.unwrap_err();
        assert!(matches!(err, BusError::Rpc { code: -32602, .. }));
        let err = c
            .call("browser.navigate", json!({"url":"https://x"}))
            .await
            .unwrap_err();
        assert!(matches!(err, BusError::Tool(_)));
    }

    #[tokio::test]
    async fn agent_scope_and_poc_commands() {
        let (c, _) = client();
        let a = c.call("agent.status", json!({})).await.unwrap();
        assert_eq!(a["policy"], "all");
        c.call("agent.set", json!({"policy":"paused"}))
            .await
            .unwrap();
        assert_eq!(
            c.call("agent.status", json!({})).await.unwrap()["policy"],
            "paused"
        );
        c.call("scope.add", json!({"host":"*.other.test"}))
            .await
            .unwrap();
        assert_eq!(
            c.call("scope.list", json!({}))
                .await
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            4
        );
        let p = c
            .call("poc.build", json!({"flow_id":"f48","name":"Reflected XSS"}))
            .await
            .unwrap();
        assert_eq!(p, "pocs/reflected-xss.yaml");
        let r = c
            .call("poc.run", json!({"poc_path":"pocs/reflected-xss.yaml"}))
            .await
            .unwrap();
        assert_eq!(r["passed"], true);
        assert_eq!(
            c.call("poc.list", json!({}))
                .await
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            3
        );
    }
}
