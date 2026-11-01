//! The bus task: the one place the TUI talks to the proxy. It connects
//! (initialize → tools/list), polls `flow.list` + `flow.get` on a timer (F4
//! push is not on the bus yet, foundation §4.4), runs the app's [`BusRequest`]s
//! and reports everything as [`BusEvent`]s. Features the bus does not offer
//! are simply not polled: the app reads `tools/list` and degrades (§2.10).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use aitm_bus_client::{BusClient, BusError};
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::action::{BusEvent, BusRequest, Level, ToolInfo};
use crate::l4::{flow_get_args, fold_status, slow_l4_reads, supports_window, L4Availability};
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
    /// What `l4.capture.status` said last (L4 parity spec §1); pending until
    /// the first slow pass, re-read on every one, never cached for the session.
    capture: L4Availability,
    /// What `l4.intercept.status` said last; gates the `l4.intercept.list` read.
    intercept: L4Availability,
    /// The running capture ids from the last `l4.capture.status`.
    captures: Vec<String>,
}

impl Session {
    fn new(client: Arc<BusClient>, tx: mpsc::Sender<BusEvent>) -> Self {
        Self {
            client,
            tx,
            tools: Vec::new(),
            summaries: HashMap::new(),
            polls: 0,
            capture: L4Availability::pending(),
            intercept: L4Availability::pending(),
            captures: Vec::new(),
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
        self.proxy_status().await
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
            self.l4_slow_pass().await?;
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

    /// The slow `l4.*` reads (L4 parity spec §1, §4), walking
    /// [`slow_l4_reads`] in its order: the scope and agent panels; both status
    /// verbs every pass, folded through [`fold_status`] (an `L4 unavailable: `
    /// tool error is an honest unavailable, never a toast) and reported as one
    /// [`BusEvent::L4Availability`]; `l4.intercept.list` only while the last
    /// `l4.intercept.status` said available. A transport failure ends the
    /// session like anywhere else.
    async fn l4_slow_pass(&mut self) -> Result<(), Outcome> {
        let reads = slow_l4_reads(|t| self.has(t), self.intercept.available);
        let mut status_read = false;
        for name in reads {
            match name {
                "l4.scope.list" => {
                    if let Value::Array(entries) = self.panel(name).await? {
                        self.emit(BusEvent::L4Scope(entries)).await?;
                    }
                }
                "l4.agent.status" => {
                    let v = self.panel(name).await?;
                    if v.is_object() {
                        self.emit(BusEvent::L4Agent(v)).await?;
                    }
                }
                "l4.capture.status" => {
                    let (availability, ids) = self.status(name, "captures").await?;
                    self.capture = availability;
                    self.captures = ids;
                    status_read = true;
                }
                "l4.intercept.status" => {
                    let (availability, _) = self.status(name, "sessions").await?;
                    self.intercept = availability;
                    status_read = true;
                }
                "l4.intercept.list" => {
                    // Listed because the previous status said available; the
                    // status just read above may have withdrawn that.
                    if !self.intercept.available {
                        continue;
                    }
                    if let Value::Array(parked) = self.panel(name).await? {
                        self.emit(BusEvent::L4Parked(parked)).await?;
                    }
                }
                _ => {}
            }
        }
        if status_read {
            self.emit(BusEvent::L4Availability {
                capture: self.capture.clone(),
                intercept: self.intercept.clone(),
                captures: self.captures.clone(),
            })
            .await?;
        }
        Ok(())
    }

    /// Read one status verb (`l4.capture.status` / `l4.intercept.status`) and
    /// fold it: a reply or a tool error through [`fold_status`]; a transport
    /// failure ends the session.
    async fn status(
        &self,
        name: &str,
        key: &str,
    ) -> Result<(L4Availability, Vec<String>), Outcome> {
        let outcome = match self.client.call(name, json!({})).await {
            Ok(v) => Ok(v),
            Err(BusError::Transport(e)) => return Err(Outcome::Lost(format!("{e:#}"))),
            Err(e) => Err(error_text(e)),
        };
        Ok(fold_status(outcome.as_ref().map_err(String::as_str), key))
    }

    /// One pass over the L4 flow store (ui-ext Part 3): `l4.flow.list` → ids,
    /// `l4.flow.get` per id with `limit: 0` on a core that declares the §2
    /// window (flow fields only; the inspector fetches packets). A per-flow
    /// tool error is skipped (the flow keeps what the app has); only a dead
    /// transport ends the session.
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
        let window = supports_window(&self.tools);
        let mut flows = Vec::with_capacity(ids.len());
        for id in &ids {
            match self
                .client
                .call("l4.flow.get", flow_get_args(id, window))
                .await
            {
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
        };
        let args = self.prune(name, args);
        self.call_and_report(name, args).await
    }

    /// Drop arguments the tool's schema does not declare, so a form built for
    /// a richer schema still works against an older core ([`prune_args`]).
    fn prune(&self, name: &str, args: Value) -> Value {
        prune_args(self.tools.iter().find(|t| t.name == name), args)
    }

    async fn call_and_report(&mut self, name: &str, args: Value) -> Result<(), Outcome> {
        if !self.has(name) {
            return self
                .emit(BusEvent::CallFailed {
                    name: name.to_string(),
                    message: format!("{name} is not on this bus"),
                })
                .await;
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
                self.emit(BusEvent::CallOk {
                    name: name.to_string(),
                    value,
                })
                .await
            }
            Err(e) => self.call_failed(name, e).await,
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

/// The reserved confirm-over-the-wire acknowledgment (spec D4): the server
/// strips it before schema enforcement, so no `inputSchema` declares it and
/// [`prune_args`] must never drop it.
const CONFIRM_KEY: &str = "_confirm";

/// Drop the arguments `tool`'s `inputSchema` does not declare, so a form built
/// for a richer schema still works against an older core. No tool, no
/// `properties`, or an empty one: `args` pass untouched. [`CONFIRM_KEY`] is
/// always kept: it is the MCP-local handshake token, not a tool argument.
fn prune_args(tool: Option<&ToolInfo>, args: Value) -> Value {
    let Some(tool) = tool else {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The confirm-over-the-wire re-issue (`l4.inject`, `l4.scope.add`, …)
    /// carries the reserved `_confirm` token, which no tool's `inputSchema`
    /// declares (the server strips it before schema enforcement). Pruning must
    /// keep it, or every confirmed call is re-sent bare and the core answers
    /// with another `needs_confirmation` (live run on the L4 rig, task B9).
    /// Undeclared ordinary keys are still dropped.
    #[test]
    fn prune_keeps_the_reserved_confirm_token() {
        let tool = ToolInfo {
            name: "l4.scope.add".into(),
            description: String::new(),
            input_schema: json!({
                "type": "object",
                "properties": {"cidr": {"type": "string"}, "ports": {"type": "string"}},
                "required": ["cidr"]
            }),
            confirmable: true,
        };
        let pruned = prune_args(
            Some(&tool),
            json!({"cidr": "127.0.0.1/32", "ports": "9100-9199", "bogus": 1, "_confirm": "cfm_1"}),
        );
        assert_eq!(
            pruned,
            json!({"cidr": "127.0.0.1/32", "ports": "9100-9199", "_confirm": "cfm_1"})
        );
        // No schema to prune against: untouched, token included.
        assert_eq!(
            prune_args(None, json!({"a": 1, "_confirm": "t"})),
            json!({"a": 1, "_confirm": "t"})
        );
    }

    // ---------------------------------------------------------- tester: Session
    //
    // Stage-5 additions (L4 parity unit (b), tester). The bus *task* is driven
    // through a recording in-memory transport, so what reaches the wire is
    // asserted at the level that matters: `l4_slow_pass` never asks for
    // `l4.intercept.list` while intercept is unavailable and re-reads both
    // status verbs every pass; `l4_poll` sends `limit: 0` only when the core
    // declares the window; `handle` keeps `_confirm` for every confirmable
    // L4 verb. No socket, no fixture: every reply is built here.

    use aitm_bus_client::{BusClient, BusTransport};
    use futures::future::BoxFuture;
    use std::sync::{Arc as StdArc, Mutex as StdMutex};

    type Calls = StdArc<StdMutex<Vec<(String, Value)>>>;
    type Answer = StdArc<dyn Fn(&str, &Value) -> Result<Value, String> + Send + Sync>;

    /// A recording bus: every `tools/call` lands in `calls`; `answer` decides
    /// the reply (`Ok` → `structuredContent`, `Err(text)` → an `isError` tool
    /// error, the shape `aitm-mcp` sends). Other methods answer `{}`.
    struct RecordingBus {
        calls: Calls,
        answer: Answer,
    }

    impl BusTransport for RecordingBus {
        fn send(&self, line: String) -> BoxFuture<'_, anyhow::Result<Option<String>>> {
            let req: Value = serde_json::from_str(&line).expect("the client sends JSON");
            let Some(id) = req.get("id").filter(|i| !i.is_null()).cloned() else {
                return Box::pin(async { Ok(None) });
            };
            let result = match req["method"].as_str() {
                Some("tools/call") => {
                    let name = req["params"]["name"].as_str().unwrap_or("").to_string();
                    let args = req["params"]["arguments"].clone();
                    self.calls
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push((name.clone(), args.clone()));
                    match (self.answer)(&name, &args) {
                        Ok(v) => json!({
                            "content": [{"type": "text", "text": v.to_string()}],
                            "structuredContent": v
                        }),
                        Err(text) => json!({
                            "isError": true,
                            "content": [{"type": "text", "text": text}]
                        }),
                    }
                }
                _ => json!({}),
            };
            let reply = json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string();
            Box::pin(async move { Ok(Some(reply)) })
        }
    }

    fn session(answer: Answer) -> (Session, Calls, mpsc::Receiver<BusEvent>) {
        let calls: Calls = StdArc::new(StdMutex::new(Vec::new()));
        let client = StdArc::new(BusClient::new(Box::new(RecordingBus {
            calls: calls.clone(),
            answer,
        })));
        let (tx, rx) = mpsc::channel(1024);
        (Session::new(client, tx), calls, rx)
    }

    fn tool(name: &str, props: &[&str]) -> ToolInfo {
        let mut properties = serde_json::Map::new();
        for p in props {
            properties.insert((*p).to_string(), json!({"type": "string"}));
        }
        ToolInfo {
            name: name.to_string(),
            description: String::new(),
            input_schema: json!({"type": "object", "properties": properties}),
            confirmable: false,
        }
    }

    fn names(calls: &Calls) -> Vec<String> {
        calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(n, _)| n.clone())
            .collect()
    }

    fn args_of(calls: &Calls, name: &str) -> Vec<Value> {
        calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, a)| a.clone())
            .collect()
    }

    fn clear(calls: &Calls) {
        calls.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    fn drain(rx: &mut mpsc::Receiver<BusEvent>) -> Vec<BusEvent> {
        let mut out = Vec::new();
        while let Ok(e) = rx.try_recv() {
            out.push(e);
        }
        out
    }

    const AC3: &str =
        r#"{"available": false, "code": "needs_privilege", "reason": "R_CAP", "captures": []}"#;
    const AC4: &str = r#"{"available": false, "code": "unsupported_platform", "reason": "R_INT", "sessions": []}"#;

    fn v(s: &str) -> Value {
        serde_json::from_str(s).expect("literal JSON")
    }

    /// Spec §1 + §4 at the bus task: both status verbs are read on **every**
    /// slow pass (never cached), `l4.intercept.list` is never requested while
    /// the last `l4.intercept.status` said unavailable, it is requested once
    /// the core says available (and the parked list reaches the app), and it
    /// stops again the pass after the core withdraws availability — even
    /// though that pass's read list was planned while it was still available.
    #[tokio::test]
    async fn l4_slow_pass_reads_statuses_every_pass_and_gates_the_parked_list_on_availability() {
        let intercept_on = StdArc::new(StdMutex::new(false));
        let flag = intercept_on.clone();
        let answer: Answer = StdArc::new(move |name: &str, _args: &Value| match name {
            "l4.scope.list" => Ok(json!([])),
            "l4.agent.status" => {
                Ok(json!({"capture": false, "inject": false, "intercept": false, "widen": false}))
            }
            "l4.capture.status" => Ok(v(AC3)),
            "l4.intercept.status" => Ok(if *flag.lock().unwrap_or_else(|e| e.into_inner()) {
                json!({"available": true, "code": "available", "reason": null, "sessions": ["F"]})
            } else {
                v(AC4)
            }),
            "l4.intercept.list" => Ok(json!([{
                "id": "P1", "flow": "F", "state": "parked", "dir": "inbound",
                "length": 60, "layers": ["IPv4", "TCP"], "parked_at": 1_700_000_000_000i64
            }])),
            other => Err(format!("{other}: unexpected call")),
        });
        let (mut s, calls, mut rx) = session(answer);
        s.tools = [
            "l4.scope.list",
            "l4.agent.status",
            "l4.capture.status",
            "l4.intercept.status",
            "l4.intercept.list",
        ]
        .iter()
        .map(|n| tool(n, &[]))
        .collect();

        // Pass 1 and 2: exactly the four reads each time, in order.
        for pass in 1..=2 {
            clear(&calls);
            assert!(s.l4_slow_pass().await.is_ok());
            assert_eq!(
                names(&calls),
                vec![
                    "l4.scope.list",
                    "l4.agent.status",
                    "l4.capture.status",
                    "l4.intercept.status"
                ],
                "pass {pass}"
            );
            let events = drain(&mut rx);
            let availability = events
                .iter()
                .find_map(|e| match e {
                    BusEvent::L4Availability {
                        capture,
                        intercept,
                        captures,
                    } => Some((capture.clone(), intercept.clone(), captures.clone())),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("pass {pass}: no L4Availability event in {events:?}"));
            assert_eq!(availability.0.code.as_deref(), Some("needs_privilege"));
            assert_eq!(availability.0.reason.as_deref(), Some("R_CAP"));
            assert!(!availability.0.available);
            assert_eq!(availability.1.code.as_deref(), Some("unsupported_platform"));
            assert_eq!(availability.1.reason.as_deref(), Some("R_INT"));
            assert!(availability.2.is_empty());
            assert!(
                !events.iter().any(|e| matches!(e, BusEvent::L4Parked(_))),
                "pass {pass}: no parked list while unavailable: {events:?}"
            );
            assert!(
                !events
                    .iter()
                    .any(|e| matches!(e, BusEvent::Toast(..) | BusEvent::CallFailed { .. })),
                "pass {pass}: an availability read never toasts: {events:?}"
            );
        }

        // The core becomes able to intercept (D0 at runtime). Within two
        // passes the parked list is read and reaches the app.
        *intercept_on.lock().unwrap_or_else(|e| e.into_inner()) = true;
        clear(&calls);
        let mut events = Vec::new();
        for _ in 0..2 {
            assert!(s.l4_slow_pass().await.is_ok());
            events.extend(drain(&mut rx));
        }
        assert!(
            names(&calls).iter().any(|n| n == "l4.intercept.list"),
            "the parked list is read once intercept is available: {:?}",
            names(&calls)
        );
        assert_eq!(
            names(&calls)
                .iter()
                .filter(|n| *n == "l4.intercept.status")
                .count(),
            2,
            "the status is still re-read every pass"
        );
        let parked = events
            .iter()
            .find_map(|e| match e {
                BusEvent::L4Parked(p) => Some(p.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no L4Parked event in {events:?}"));
        assert_eq!(parked[0]["id"], json!("P1"));
        assert!(events.iter().any(|e| matches!(
            e,
            BusEvent::L4Availability { intercept, .. } if intercept.available
        )));

        // The core withdraws it: the very next pass skips the list, although
        // the previous status had planned it, and so does every later pass.
        *intercept_on.lock().unwrap_or_else(|e| e.into_inner()) = false;
        for pass in 1..=2 {
            clear(&calls);
            assert!(s.l4_slow_pass().await.is_ok());
            assert!(
                !names(&calls).iter().any(|n| n == "l4.intercept.list"),
                "after withdrawal, pass {pass}: {:?}",
                names(&calls)
            );
            let events = drain(&mut rx);
            assert!(!events.iter().any(|e| matches!(e, BusEvent::L4Parked(_))));
        }
    }

    /// Spec §1 compatibility at the bus task: an older core's `L4 unavailable:`
    /// tool error on a status verb folds into availability (reason = the text
    /// after the marker) with no toast and no `CallFailed`; any other tool
    /// error is an honest unavailable with its text; a core without the verbs
    /// is never asked and gets no availability event at all.
    #[tokio::test]
    async fn l4_slow_pass_folds_tool_errors_into_availability_without_a_toast() {
        let answer: Answer = StdArc::new(|name: &str, _: &Value| match name {
            "l4.capture.status" => Err("l4.capture.status: L4 unavailable: X".to_string()),
            "l4.intercept.status" => Err("internal error (-32603)".to_string()),
            other => Err(format!("{other}: unexpected call")),
        });
        let (mut s, calls, mut rx) = session(answer);
        s.tools = vec![
            tool("l4.capture.status", &[]),
            tool("l4.intercept.status", &[]),
        ];
        assert!(s.l4_slow_pass().await.is_ok());
        assert_eq!(
            names(&calls),
            vec!["l4.capture.status", "l4.intercept.status"]
        );
        let events = drain(&mut rx);
        assert_eq!(events.len(), 1, "{events:?}");
        let BusEvent::L4Availability {
            capture,
            intercept,
            captures,
        } = &events[0]
        else {
            panic!("{events:?}");
        };
        assert_eq!(
            *capture,
            L4Availability {
                available: false,
                code: None,
                reason: Some("X".into()),
            }
        );
        assert_eq!(
            *intercept,
            L4Availability {
                available: false,
                code: None,
                reason: Some("internal error (-32603)".into()),
            }
        );
        assert!(captures.is_empty());

        // No `l4.*` on the bus: nothing read, nothing emitted.
        let (mut bare, calls, mut rx) = session(StdArc::new(|n: &str, _: &Value| {
            Err(format!("{n}: must not be called"))
        }));
        bare.tools = vec![tool("flow.list", &[])];
        assert!(bare.l4_slow_pass().await.is_ok());
        assert!(names(&calls).is_empty());
        assert!(drain(&mut rx).is_empty());
    }

    /// Spec §2 at the bus task: the list poll's `l4.flow.get` carries
    /// `limit: 0` exactly when the core's `inputSchema` declares `limit`, and
    /// just `{id}` against an older core — the same reply either way.
    #[tokio::test]
    async fn l4_poll_sends_limit_zero_only_when_the_core_declares_the_window() {
        let answer: Answer = StdArc::new(|name: &str, args: &Value| match name {
            "l4.flow.list" => Ok(json!(["F", "G"])),
            "l4.flow.get" => Ok(json!({
                "id": args["id"], "kind": "capture", "interface": "lo0",
                "packet_count": 3, "injected_count": 0, "packets": []
            })),
            other => Err(format!("{other}: unexpected call")),
        });
        let expected = |window: bool, id: &str| {
            if window {
                json!({"id": id, "limit": 0})
            } else {
                json!({"id": id})
            }
        };
        for declares_window in [true, false] {
            let (mut s, calls, mut rx) = session(answer.clone());
            let get_props: &[&str] = if declares_window {
                &["id", "offset", "limit"]
            } else {
                &["id"]
            };
            s.tools = vec![tool("l4.flow.list", &[]), tool("l4.flow.get", get_props)];
            assert!(s.l4_poll().await.is_ok());
            assert_eq!(
                names(&calls),
                vec!["l4.flow.list", "l4.flow.get", "l4.flow.get"],
                "window={declares_window}"
            );
            assert_eq!(
                args_of(&calls, "l4.flow.get"),
                vec![
                    expected(declares_window, "F"),
                    expected(declares_window, "G")
                ],
                "window={declares_window}"
            );
            let events = drain(&mut rx);
            let flows = events
                .iter()
                .find_map(|e| match e {
                    BusEvent::L4Flows(f) => Some(f.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("no L4Flows in {events:?}"));
            assert_eq!(flows.len(), 2);
            assert_eq!(flows[0]["id"], json!("F"));
        }
    }

    /// The `_confirm` re-issue reaches the wire intact for **every**
    /// confirmable L4 verb — `l4.inject`, `l4.scope.add`,
    /// `l4.intercept.forward`, `l4.intercept.drop` — through the real
    /// `handle` → `prune` → `call` path, against each verb's declared schema
    /// (the rig's key sets): the declared keys and `_confirm` survive, an
    /// undeclared key is dropped, and the reply comes back as `CallOk`. The
    /// B9 live run found the token pruned here; this pins the fix per verb.
    #[tokio::test]
    async fn handle_keeps_the_confirm_token_for_every_confirmable_l4_verb() {
        let answer: Answer = StdArc::new(|name: &str, args: &Value| {
            if args.get("_confirm").and_then(Value::as_str) == Some("cfm_1") {
                Ok(json!(format!("{name}: confirmed")))
            } else {
                Ok(json!({"status": "needs_confirmation", "prompt": "P", "confirm_token": "cfm_1"}))
            }
        });
        let (mut s, calls, mut rx) = session(answer);
        s.tools = vec![
            tool("l4.inject", &["spec", "dst", "interface", "count"]),
            tool(
                "l4.scope.add",
                &["cidr", "ports", "interface", "direction", "capability"],
            ),
            tool("l4.intercept.forward", &["id"]),
            tool("l4.intercept.drop", &["id"]),
        ];
        let spec = json!({"layers": [{"ipv4": {"src": "127.0.0.1", "dst": "127.0.0.1"}}, {"udp": {"src_port": 40000, "dst_port": 9053}}]});
        let cases: Vec<(&str, Value)> = vec![
            (
                "l4.inject",
                json!({"spec": spec, "interface": "lo0", "dst": "127.0.0.1"}),
            ),
            (
                "l4.scope.add",
                json!({"cidr": "127.0.0.1/32", "ports": "9100-9199", "interface": "lo0",
                       "direction": "inbound", "capability": "capture"}),
            ),
            ("l4.intercept.forward", json!({"id": "P1"})),
            ("l4.intercept.drop", json!({"id": "P1"})),
        ];
        for (call, original) in cases {
            // What the app sends on `y`: the originals plus the token (and a
            // stray undeclared key, to prove pruning still happens).
            let confirm = crate::l4::L4Confirm {
                call: call.to_string(),
                args: original.clone(),
                prompt: "P".into(),
                token: "cfm_1".into(),
            };
            let mut sent = confirm.confirmed_args();
            sent["bogus"] = json!(1);
            clear(&calls);
            assert!(s
                .handle(BusRequest::Call {
                    name: call.to_string(),
                    args: sent,
                })
                .await
                .is_ok());
            let on_wire = args_of(&calls, call);
            assert_eq!(on_wire.len(), 1, "{call}: {on_wire:?}");
            let mut expected = original.clone();
            expected["_confirm"] = json!("cfm_1");
            assert_eq!(
                on_wire[0], expected,
                "{call}: the token survives pruning, `bogus` does not"
            );
            let events = drain(&mut rx);
            assert!(
                events.iter().any(|e| matches!(
                    e,
                    BusEvent::CallOk { name, value } if name == call && *value == json!(format!("{call}: confirmed"))
                )),
                "{call}: the confirmed reply reaches the app: {events:?}"
            );
            // And a first issue without the token is sent bare (no token
            // invented client-side) and earns the handshake.
            clear(&calls);
            assert!(s
                .handle(BusRequest::Call {
                    name: call.to_string(),
                    args: original.clone(),
                })
                .await
                .is_ok());
            assert_eq!(args_of(&calls, call), vec![original.clone()], "{call}");
            let events = drain(&mut rx);
            assert!(
                events.iter().any(|e| matches!(
                    e,
                    BusEvent::CallOk { name, value } if name == call && value["status"] == json!("needs_confirmation")
                )),
                "{call}: {events:?}"
            );
        }
    }

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
