//! The bus task: the one place the TUI talks to the proxy. It connects
//! (initialize → tools/list → proxy.status → flow.subscribe), polls
//! `flow.list` + `flow.get` on a timer (push lines are a trigger, the poll is
//! the truth; scanner v2 D5/D6), runs the app's [`BusRequest`]s and reports
//! everything as [`BusEvent`]s. Features the bus does not offer are simply
//! not polled: the app reads `tools/list` and degrades (§2.10).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use aitm_bus_client::{BusClient, BusError};
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::action::{BusEvent, BusRequest, Level, ToolInfo};
use crate::model::{AgentState, Finding, FlowDetail, ProxyStatus};

/// Client name sent in `initialize.clientInfo` (§4.2).
pub const CLIENT_NAME: &str = "aitm-tui";
/// Client version sent in `initialize.clientInfo`.
pub const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Makes a fresh client; called again with back-off after a transport failure.
pub type Connector =
    Arc<dyn Fn() -> aitm_bus_client::BoxFuture<'static, anyhow::Result<BusClient>> + Send + Sync>;

/// The JSON-RPC code `aitm-mcp` answers a wrong token with (foundation §4.1).
const UNAUTHORIZED: i64 = -32001;

/// The reserved argument a confirm-over-the-wire re-issue carries
/// (`server.rs` `needs_confirmation`); never declared by any tool schema.
const CONFIRM_KEY: &str = "_confirm";

/// What the app is told when the bus refuses the token; retrying cannot fix it.
/// Worded for either intended role and without implying the token came from a
/// file (it may be `--token`, `--token-file`, or `AITM_BUS_TOKEN`).
pub const REFUSED: &str = "bus refused the token: it matched neither the agent nor the operator token (check the token you supplied)";

/// Run until the app goes away: the request channel closes, or an event
/// cannot be delivered because its receiver is gone. A failed connect or a
/// lost transport never ends the loop; it is retried with exponential
/// back-off (500 ms doubling to 10 s, reset after each successful connect).
/// The one exception is a token refusal during the handshake: that is
/// reported as [`REFUSED`] and the task stops, since no retry can succeed.
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
            Outcome::Refused(why) => {
                let _ = tx.send(BusEvent::Disconnected(why)).await;
                return;
            }
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
    /// The bus rejected our token during the handshake; do not reconnect.
    Refused(String),
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
            .map_err(|e| match e {
                BusError::Rpc {
                    code: UNAUTHORIZED, ..
                } => Outcome::Refused(REFUSED.to_string()),
                other => lost(other),
            })?;
        self.tools = self.client.tools_list().await.map_err(lost)?;
        self.emit(BusEvent::Connected {
            server: format!("{} {}", info.name, info.version),
            tools: self.tools.clone(),
            role: info.role.clone(),
        })
        .await?;
        // `proxy.status` is read-only: a tool error here leaves the state
        // unknown and the session alive; only a dead transport ends it.
        self.proxy_status().await?;
        self.subscribe().await
    }

    /// Subscribe to server pushes once per connection (scanner v2 D5): when
    /// the bus offers `flow.subscribe`, call it with no filter so job and
    /// flow lines reach this connection. A tool error is a warning, not a
    /// session loss: the poll cadence still carries scan progress. The
    /// result value is ignored.
    async fn subscribe(&self) -> Result<(), Outcome> {
        if !self.has("flow.subscribe") {
            return Ok(());
        }
        match self.client.call("flow.subscribe", json!({})).await {
            Ok(_) => Ok(()),
            Err(BusError::Transport(e)) => Err(Outcome::Lost(format!("{e:#}"))),
            Err(e) => {
                let msg = error_text(e);
                self.emit(BusEvent::Toast(
                    Level::Warn,
                    format!("flow.subscribe failed: {msg}; scan progress will poll only"),
                ))
                .await
            }
        }
    }

    /// Read `proxy.status` (F7) when the bus has it and report it.
    async fn proxy_status(&self) -> Result<(), Outcome> {
        if !self.has("proxy.status") {
            return Ok(());
        }
        let v = self.panel("proxy.status").await?;
        if v.is_object() {
            self.emit(BusEvent::ProxyStatus(ProxyStatus::from_json(&v)))
                .await?;
        }
        Ok(())
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
            Err(e) => return self.call_failed("flow.list", e).await,
        };
        let mut out = Vec::with_capacity(ids.len());
        // The first per-flow failure of this pass, reported once below: a row
        // whose `flow.get` fails keeps its cached summary rather than vanishing
        // (the app would evict it and drop the selection).
        let mut first_failure: Option<(String, String)> = None;
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
                    Err(e) => {
                        if first_failure.is_none() {
                            first_failure = Some((id.clone(), error_text(e)));
                        }
                    }
                }
            }
            if let Some(s) = self.summaries.get(id) {
                out.push(s.clone());
            }
        }
        let live: HashSet<&str> = ids.iter().map(String::as_str).collect();
        self.summaries.retain(|k, _| live.contains(k.as_str()));
        self.emit(BusEvent::Flows(out)).await?;
        if let Some((id, why)) = first_failure {
            self.emit(BusEvent::Toast(
                Level::Warn,
                format!("flow.get {id}: {why}"),
            ))
            .await?;
        }

        if self.polls % 6 == 1 {
            if self.has("scope.list") {
                if let Value::Array(entries) = self.panel("scope.list").await? {
                    let scope = entries
                        .into_iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect();
                    self.emit(BusEvent::Scope(scope)).await?;
                }
            }
            if self.has("agent.status") {
                let v = self.panel("agent.status").await?;
                if !v.is_null() {
                    let mut a = AgentState::default();
                    a.apply_status(&v);
                    self.emit(BusEvent::Agent(a)).await?;
                }
            }
            if self.has("l4.scope.list") {
                if let Value::Array(entries) = self.panel("l4.scope.list").await? {
                    self.emit(BusEvent::L4Scope(entries)).await?;
                }
            }
            if self.has("l4.agent.status") {
                let v = self.panel("l4.agent.status").await?;
                if v.is_object() {
                    self.emit(BusEvent::L4Agent(v)).await?;
                }
            }
            if self.has("poc.list") {
                if let Value::Array(items) = self.panel("poc.list").await? {
                    let findings = items.iter().filter_map(Finding::from_json).collect();
                    self.emit(BusEvent::Findings(findings)).await?;
                }
            }
            if self.has("findings.list") {
                let v = self.panel("findings.list").await?;
                if let Some(items) = v.get("findings").and_then(Value::as_array) {
                    let findings = items.iter().filter_map(Finding::from_script_json).collect();
                    self.emit(BusEvent::ScriptFindings(findings)).await?;
                }
            }
            self.proxy_status().await?;
        }
        // The L4 flow pass (ui-ext Part 3), feature-detected and polled every
        // pass like the HTTP flow list; absent on a bus without the `l4.*`
        // surface. Last, so it never reorders the HTTP fast/slow sequence.
        if self.has("l4.flow.list") && self.has("l4.flow.get") {
            self.l4_poll().await?;
        }
        Ok(())
    }

    /// One pass over the L4 flow store (ui-ext Part 3): `l4.flow.list` → ids,
    /// `l4.flow.get` per id. A per-flow tool error is skipped (the flow keeps
    /// what the app has); only a dead transport ends the session.
    async fn l4_poll(&mut self) -> Result<(), Outcome> {
        let ids = match self.client.call("l4.flow.list", json!({})).await {
            Ok(Value::Array(ids)) => ids
                .into_iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect::<Vec<_>>(),
            Ok(_) => Vec::new(),
            Err(BusError::Transport(e)) => return Err(Outcome::Lost(format!("{e:#}"))),
            Err(e) => return self.call_failed("l4.flow.list", e).await,
        };
        let mut flows = Vec::with_capacity(ids.len());
        for id in &ids {
            match self.client.call("l4.flow.get", json!({ "id": id })).await {
                Ok(v) => flows.push(v),
                Err(BusError::Transport(e)) => return Err(Outcome::Lost(format!("{e:#}"))),
                Err(_) => {}
            }
        }
        self.emit(BusEvent::L4Flows(flows)).await
    }

    /// Read a slow-changing panel. A transport failure ends the session like
    /// anywhere else; a tool or protocol error leaves the panel as it was
    /// (`Null`) — it is re-read on the next slow pass, no toast every 3 s.
    async fn panel(&self, name: &str) -> Result<Value, Outcome> {
        match self.client.call(name, json!({})).await {
            Ok(v) => Ok(v),
            Err(BusError::Transport(e)) => Err(Outcome::Lost(format!("{e:#}"))),
            Err(_) => Ok(Value::Null),
        }
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
                        None => {
                            self.emit(BusEvent::DetailFailed(id.clone())).await?;
                            self.emit(BusEvent::Toast(
                                Level::Warn,
                                format!("flow.detail {id}: malformed reply"),
                            ))
                            .await
                        }
                    },
                    Err(e) => self.call_failed("flow.detail", e).await,
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
            BusRequest::PocRun {
                poc_path,
                target,
                vars,
            } => {
                let mut a = json!({ "poc_path": poc_path });
                if let Some(t) = target {
                    a["target"] = Value::String(t);
                }
                if let Some(v) = vars {
                    a["vars"] = v;
                }
                ("poc.run", a)
            }
            BusRequest::AgentSet(p) => ("agent.set", json!({ "policy": p.wire() })),
            // F7: pause and resume are two parameterless tools.
            BusRequest::ProxyPause(true) => ("proxy.pause", json!({})),
            BusRequest::ProxyPause(false) => ("proxy.resume", json!({})),
            BusRequest::ClearFlows => ("flow.clear", json!({})),
            BusRequest::PocGet(path) => ("poc.get", json!({ "poc_path": path })),
            BusRequest::Mark { id, marks } => ("flow.mark", json!({ "id": id, "marks": marks })),
            BusRequest::Comment { id, text } => ("flow.comment", json!({ "id": id, "text": text })),
            BusRequest::Import(path) => ("flow.import", json!({ "path": path })),
            BusRequest::Call { name, args } => {
                let args = self.prune(&name, args);
                return self.call_and_report(&name, args).await;
            }
            BusRequest::CallTagged { tag, name, args } => {
                let args = self.prune(&name, args);
                return self.call_and_report_tagged(&tag, &name, args).await;
            }
        };
        let args = self.prune(name, args);
        self.call_and_report(name, args).await
    }

    /// Drop arguments the tool's schema does not declare, so a form built for
    /// a richer schema still works against an older core. The reserved
    /// [`CONFIRM_KEY`] is always kept: no schema declares it (the server
    /// strips it itself), yet a confirm-over-the-wire re-issue is only a
    /// confirmation if it reaches the server.
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
                    .filter(|(k, _)| k == CONFIRM_KEY || props.contains_key(k))
                    .collect(),
            ),
            other => other,
        }
    }

    async fn call_and_report(&mut self, name: &str, args: Value) -> Result<(), Outcome> {
        match self.perform(name, args).await? {
            Ok(value) => {
                self.emit(BusEvent::CallOk {
                    name: name.to_string(),
                    value,
                })
                .await
            }
            Err(message) => {
                self.emit(BusEvent::CallFailed {
                    name: name.to_string(),
                    message,
                })
                .await
            }
        }
    }

    /// [`Self::call_and_report`] for a [`BusRequest::CallTagged`]: the same
    /// call, the same failure texts, the reply echoing `tag` verbatim as
    /// [`BusEvent::CallTaggedOk`] or [`BusEvent::CallTaggedFailed`]. The
    /// task never reads the tag; which verbs use it is the reducer's business.
    async fn call_and_report_tagged(
        &mut self,
        tag: &str,
        name: &str,
        args: Value,
    ) -> Result<(), Outcome> {
        match self.perform(name, args).await? {
            Ok(value) => {
                self.emit(BusEvent::CallTaggedOk {
                    tag: tag.to_string(),
                    name: name.to_string(),
                    value,
                })
                .await
            }
            Err(message) => {
                self.emit(BusEvent::CallTaggedFailed {
                    tag: tag.to_string(),
                    name: name.to_string(),
                    message,
                })
                .await
            }
        }
    }

    /// Run one `tools/call` the app asked for. The outer `Err` is a dead
    /// transport (the session ends like anywhere else); the inner `Err` is
    /// the operator-facing text of a refusal: the bus does not offer `name`
    /// (never sent), or the tool, RPC or protocol error it answered with.
    async fn perform(&mut self, name: &str, args: Value) -> Result<Result<Value, String>, Outcome> {
        if !self.has(name) {
            return Ok(Err(format!("{name} is not on this bus")));
        }
        // A mutation changes rows: forget the summary of the flow it names so
        // the next poll re-reads that one. Only the whole-store commands
        // invalidate everything; new flows are not cached yet anyway.
        let touched = args.get("id").and_then(Value::as_str).map(str::to_string);
        match self.client.call(name, args).await {
            Ok(value) => {
                match name {
                    "flow.clear" | "flow.import" => self.summaries.clear(),
                    _ => {
                        if let Some(id) = touched {
                            self.summaries.remove(&id);
                        }
                    }
                }
                Ok(Ok(value))
            }
            Err(BusError::Transport(e)) => Err(Outcome::Lost(format!("{e:#}"))),
            Err(other) => Ok(Err(error_text(other))),
        }
    }

    /// A `tools/call` of `name` did not complete. A transport failure ends
    /// the session like anywhere else; a tool, RPC or protocol error is the
    /// app's [`BusEvent::CallFailed`] with the operator-facing text.
    async fn call_failed(&self, name: &str, e: BusError) -> Result<(), Outcome> {
        match e {
            BusError::Transport(e) => Err(Outcome::Lost(format!("{e:#}"))),
            other => {
                self.emit(BusEvent::CallFailed {
                    name: name.to_string(),
                    message: error_text(other),
                })
                .await
            }
        }
    }
}

fn lost(e: BusError) -> Outcome {
    Outcome::Lost(e.to_string())
}

/// The operator-facing text of a non-transport error.
fn error_text(e: BusError) -> String {
    match e {
        BusError::Transport(e) => format!("{e:#}"),
        BusError::Tool(m) | BusError::Protocol(m) => m,
        BusError::Rpc { code, message } => format!("{message} ({code})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The refusal reads for either intended role and never names a file as
    /// the only token source (AC1/AC2 surface, Decision B wording). Pinned so
    /// the reword is not silently reverted.
    #[test]
    fn refused_message_reads_for_either_role_without_implying_a_file() {
        assert_eq!(
            REFUSED,
            "bus refused the token: it matched neither the agent nor the operator token (check the token you supplied)"
        );
        assert!(REFUSED.contains("agent") && REFUSED.contains("operator"));
        assert!(!REFUSED.contains("--token-file"));
    }
}
