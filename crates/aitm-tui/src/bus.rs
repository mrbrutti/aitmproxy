//! The bus task: the one place the TUI talks to the proxy. It connects
//! (initialize → tools/list), polls `flow.list` + `flow.get` on a timer (F4
//! push is not on the bus yet, foundation §4.4), runs the app's [`BusRequest`]s
//! and reports everything as [`BusEvent`]s. Features the bus does not offer
//! are simply not polled: the app reads `tools/list` and degrades (§2.10).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use aitm_bus_client::{BusClient, BusError};
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::action::{BusEvent, BusRequest, Level, ToolInfo};
use crate::model::{AgentState, Finding, FlowDetail};

/// Client name sent in `initialize.clientInfo` (§4.2).
pub const CLIENT_NAME: &str = "aitm-tui";
/// Client version sent in `initialize.clientInfo`.
pub const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Makes a fresh client; called again with back-off after a transport failure.
pub type Connector =
    Arc<dyn Fn() -> aitm_bus_client::BoxFuture<'static, anyhow::Result<BusClient>> + Send + Sync>;

/// Run until the app goes away: the request channel closes, or an event
/// cannot be delivered because its receiver is gone. A failed connect or a
/// lost transport never ends the loop; it is retried with exponential
/// back-off (500 ms doubling to 10 s, reset after each successful connect).
pub async fn run(
    connect: Connector,
    mut rx: mpsc::Receiver<BusRequest>,
    tx: mpsc::Sender<BusEvent>,
    poll_every: Duration,
) {
    let mut backoff = Duration::from_millis(500);
    loop {
        let client = match connect().await {
            Ok(c) => Arc::new(c),
            Err(e) => {
                if tx
                    .send(BusEvent::Disconnected(format!("{e:#}")))
                    .await
                    .is_err()
                {
                    return;
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(10));
                continue;
            }
        };
        backoff = Duration::from_millis(500);
        let mut session = Session::new(client, tx.clone());
        match session.serve(&mut rx, poll_every).await {
            Outcome::Closed => return,
            Outcome::Lost(why) => {
                if tx.send(BusEvent::Disconnected(why)).await.is_err() {
                    return;
                }
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

enum Outcome {
    /// The app went away.
    Closed,
    /// The transport failed; reconnect.
    Lost(String),
}

struct Session {
    client: Arc<BusClient>,
    tx: mpsc::Sender<BusEvent>,
    tools: Vec<ToolInfo>,
    /// Last summary per flow id, to skip `flow.get` on settled flows.
    summaries: HashMap<String, Value>,
    polls: u64,
}

impl Session {
    fn new(client: Arc<BusClient>, tx: mpsc::Sender<BusEvent>) -> Self {
        Self {
            client,
            tx,
            tools: Vec::new(),
            summaries: HashMap::new(),
            polls: 0,
        }
    }

    fn has(&self, tool: &str) -> bool {
        self.tools.iter().any(|t| t.name == tool)
    }

    async fn emit(&self, ev: BusEvent) -> Result<(), Outcome> {
        self.tx.send(ev).await.map_err(|_| Outcome::Closed)
    }

    async fn serve(
        &mut self,
        rx: &mut mpsc::Receiver<BusRequest>,
        poll_every: Duration,
    ) -> Outcome {
        if let Err(o) = self.handshake().await {
            return o;
        }
        let mut notes = self.client.notifications();
        let mut ticker = tokio::time::interval(poll_every);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let step = tokio::select! {
                req = rx.recv() => match req {
                    Some(r) => self.handle(r).await,
                    None => return Outcome::Closed,
                },
                _ = ticker.tick() => self.poll().await,
                line = async {
                    match notes.as_mut() {
                        Some(n) => n.recv().await.ok(),
                        None => std::future::pending().await,
                    }
                } => match line.and_then(|l| serde_json::from_str::<Value>(&l).ok()) {
                    Some(v) => self.emit(BusEvent::Notification(v)).await,
                    None => Ok(()),
                },
            };
            if let Err(o) = step {
                return o;
            }
        }
    }

    async fn handshake(&mut self) -> Result<(), Outcome> {
        let info = self
            .client
            .initialize(CLIENT_NAME, CLIENT_VERSION)
            .await
            .map_err(lost)?;
        let tools = self.client.tools_list().await.map_err(lost)?;
        self.tools = tools
            .into_iter()
            .map(|t| ToolInfo {
                name: t.name,
                description: t.description,
                input_schema: t.input_schema,
            })
            .collect();
        let listening = if self.has("proxy.status") {
            match self.client.call("proxy.status", json!({})).await {
                Ok(v) => v
                    .get("listening")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                Err(_) => None,
            }
        } else {
            None
        };
        self.emit(BusEvent::Connected {
            server: format!("{} {}", info.name, info.version),
            tools: self.tools.clone(),
            listening,
        })
        .await
    }

    /// One pass over the flow list, plus the slow-changing panels every few passes.
    async fn poll(&mut self) -> Result<(), Outcome> {
        self.polls += 1;
        let ids = match self.client.call("flow.list", json!({})).await {
            Ok(Value::Array(ids)) => ids
                .into_iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect::<Vec<_>>(),
            Ok(_) => Vec::new(),
            Err(e) => return self.report(e).await,
        };
        let mut out = Vec::with_capacity(ids.len());
        for id in &ids {
            let settled = self.summaries.get(id).is_some_and(|s| {
                s.get("status").is_some_and(|st| !st.is_null())
                    && s.get("intercept").and_then(Value::as_str) != Some("intercepted")
                    && s.get("kind").and_then(Value::as_str) != Some("websocket")
            });
            if !settled {
                match self.client.call("flow.get", json!({ "id": id })).await {
                    Ok(v) => {
                        self.summaries.insert(id.clone(), v);
                    }
                    Err(BusError::Transport(e)) => return Err(Outcome::Lost(format!("{e:#}"))),
                    Err(_) => continue,
                }
            }
            if let Some(s) = self.summaries.get(id) {
                out.push(s.clone());
            }
        }
        self.summaries.retain(|k, _| ids.contains(k));
        self.emit(BusEvent::Flows(out)).await?;

        if self.polls % 6 == 1 {
            if self.has("scope.list") {
                if let Ok(Value::Array(entries)) = self.client.call("scope.list", json!({})).await {
                    let scope = entries
                        .into_iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect();
                    self.emit(BusEvent::Scope(scope)).await?;
                }
            }
            if self.has("agent.status") {
                if let Ok(v) = self.client.call("agent.status", json!({})).await {
                    let mut a = AgentState::default();
                    a.apply_status(&v);
                    self.emit(BusEvent::Agent(a)).await?;
                }
            }
            if self.has("poc.list") {
                if let Ok(Value::Array(items)) = self.client.call("poc.list", json!({})).await {
                    let findings = items.iter().filter_map(Finding::from_json).collect();
                    self.emit(BusEvent::Findings(findings)).await?;
                }
            }
        }
        Ok(())
    }

    async fn handle(&mut self, req: BusRequest) -> Result<(), Outcome> {
        let (name, args) = match req {
            BusRequest::Refresh => return self.poll().await,
            BusRequest::Detail(id) => {
                if !self.has("flow.detail") {
                    return Ok(());
                }
                return match self
                    .client
                    .call("flow.detail", json!({ "id": id, "body": "inline" }))
                    .await
                {
                    Ok(v) => match FlowDetail::from_json(&v) {
                        Some(d) => self.emit(BusEvent::Detail(Box::new(d))).await,
                        None => Ok(()),
                    },
                    Err(e) => self.report(e).await,
                };
            }
            BusRequest::Intercept(on) => ("flow.intercept", json!({ "enabled": on })),
            BusRequest::Resume(id) => ("flow.resume", json!({ "id": id })),
            BusRequest::Kill(id) => ("flow.kill", json!({ "id": id })),
            BusRequest::Mutate { id, edits } => {
                ("flow.mutate", json!({ "id": id, "edits": edits }))
            }
            BusRequest::Replay(id) => ("flow.replay", json!({ "id": id })),
            BusRequest::Send(args) => ("request.send", args),
            BusRequest::ScopeAdd(h) => ("scope.add", json!({ "host": h })),
            BusRequest::ScopeRemove(h) => ("scope.remove", json!({ "host": h })),
            BusRequest::PocBuild {
                flow_id,
                name,
                param,
            } => {
                let mut a = json!({ "flow_id": flow_id });
                if let Some(n) = name {
                    a["name"] = Value::String(n);
                }
                if let Some(p) = param {
                    a["param"] = Value::String(p);
                }
                ("poc.build", a)
            }
            BusRequest::PocRun { poc_path, target } => {
                let mut a = json!({ "poc_path": poc_path });
                if let Some(t) = target {
                    a["target"] = Value::String(t);
                }
                ("poc.run", a)
            }
            BusRequest::AgentSet(p) => ("agent.set", json!({ "policy": p.wire() })),
            BusRequest::ProxyPause(p) => ("proxy.pause", json!({ "paused": p })),
            BusRequest::ClearFlows => ("flow.clear", json!({})),
            BusRequest::Mark { id, marks } => ("flow.mark", json!({ "id": id, "marks": marks })),
            BusRequest::Comment { id, text } => ("flow.comment", json!({ "id": id, "text": text })),
            BusRequest::Import(path) => ("flow.import", json!({ "path": path })),
            BusRequest::Call { name, args } => {
                let args = self.prune(&name, args);
                return self.call_and_report(&name, args).await;
            }
        };
        let args = self.prune(name, args);
        self.call_and_report(name, args).await
    }

    /// Drop arguments the tool's schema does not declare, so a form built for
    /// a richer schema still works against an older core.
    fn prune(&self, name: &str, args: Value) -> Value {
        let Some(tool) = self.tools.iter().find(|t| t.name == name) else {
            return args;
        };
        let Some(props) = tool
            .input_schema
            .get("properties")
            .and_then(Value::as_object)
        else {
            return args;
        };
        match args {
            Value::Object(map) if !props.is_empty() => Value::Object(
                map.into_iter()
                    .filter(|(k, _)| props.contains_key(k))
                    .collect(),
            ),
            other => other,
        }
    }

    async fn call_and_report(&mut self, name: &str, args: Value) -> Result<(), Outcome> {
        if !self.has(name) {
            return self
                .emit(BusEvent::Toast(
                    Level::Warn,
                    format!("{name} is not on this bus"),
                ))
                .await;
        }
        match self.client.call(name, args).await {
            Ok(value) => {
                // A mutation changes rows; re-read the ones we thought settled.
                self.summaries.clear();
                self.emit(BusEvent::CallOk {
                    name: name.to_string(),
                    value,
                })
                .await
            }
            Err(e) => self.report(e).await,
        }
    }

    async fn report(&self, e: BusError) -> Result<(), Outcome> {
        match e {
            BusError::Transport(e) => Err(Outcome::Lost(format!("{e:#}"))),
            BusError::Tool(m) => self.emit(BusEvent::Toast(Level::Error, m)).await,
            BusError::Rpc { code, message } => {
                self.emit(BusEvent::Toast(Level::Error, format!("{message} ({code})")))
                    .await
            }
            BusError::Protocol(m) => self.emit(BusEvent::Toast(Level::Error, m)).await,
        }
    }
}

fn lost(e: BusError) -> Outcome {
    Outcome::Lost(e.to_string())
}
