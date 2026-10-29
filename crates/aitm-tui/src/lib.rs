//! `aitm-tui` — aitmproxy's terminal operator UI (foundation §2.10(c)).
//!
//! A ratatui client of the command bus: the same flow list, inspector,
//! intercept bar, compose, scope, PoC and agent surfaces as the macOS and web
//! apps, drawn with the shared tokens and degraded the way §2.9 spells out.
//! It talks to the proxy through [`aitm_bus_client`] over loopback TCP, over an
//! in-process handler when `aitm tui` embeds the proxy, or against the
//! recorded fixture for UI development.
//!
//! Structure: [`app`] holds the state and reducer, [`bus`] the one task that
//! talks to the proxy, [`ui`] and [`viewers`] draw, [`snapshot`] renders
//! off-screen, [`fixture`] serves the recorded bus, [`open`] hands a file to
//! the desktop for `o`.

pub mod action;
pub mod app;
pub mod base64;
pub mod bus;
pub mod caps;
pub mod clipboard;
pub mod filter;
pub mod fixture;
pub mod keys;
pub mod model;
pub mod open;
pub mod snapshot;
pub mod theme;
pub mod tokens;
pub mod ui;
pub mod viewers;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use aitm_bus_client::{BusClient, InProcessHandler, InProcessTransport, TcpTransport};
use crossterm::event::{Event, EventStream};
use futures::StreamExt as _;
use serde_json::Value;
use tokio::sync::mpsc;

use crate::action::{Action, BusEvent, BusRequest, Level, ToolInfo};
use crate::app::App;
use crate::caps::TermCaps;
use crate::fixture::{Fixture, FixtureTransport};
use crate::model::{AgentState, Finding, FlowDetail, ProxyStatus};
use crate::theme::Theme;

/// Where the UI gets its bus.
pub enum TransportChoice {
    /// A running proxy's loopback TCP transport.
    Tcp { addr: SocketAddr, token: String },
    /// The recorded fixture (built-in when `None`).
    Fixture(Option<PathBuf>),
    /// `aitm tui`: the proxy in this process; the handler is `McpServer::handle`.
    InProcess(InProcessHandler),
}

/// How to run.
pub struct RunOptions {
    pub transport: TransportChoice,
    /// Override detected capabilities (`--ansi`, `--truecolor`).
    pub caps: Option<TermCaps>,
    /// Flow-list poll interval (F4 push is not on the bus yet).
    pub poll: Duration,
    /// A note shown in the status bar at start (e.g. where the embedded
    /// proxy's log went).
    pub startup_note: Option<String>,
    /// The proxy's listen address when the caller knows it (the embed does);
    /// otherwise it comes from `proxy.status` (F7) or stays unknown.
    pub listening: Option<String>,
    /// Where a built PoC is written (`poc.build` answers with the YAML text,
    /// not a path): the embed passes `poc.dir`, the standalone client
    /// `--poc-dir`. `None` falls back to `config.get`'s `poc_dir`, then a
    /// temp directory the toast names.
    pub poc_dir: Option<PathBuf>,
}

/// Restores the terminal when dropped, so a caller that drops the `run`
/// future mid-flight (the embedded proxy ending first, a signal) never leaves
/// the shell in raw mode on the alternate screen.
struct TerminalGuard {
    bus_task: tokio::task::JoinHandle<()>,
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        ratatui::restore();
        self.bus_task.abort();
    }
}

/// Build the connector for a transport choice, plus the address label the
/// status bar shows.
pub fn connector(choice: TransportChoice) -> anyhow::Result<(bus::Connector, String)> {
    Ok(match choice {
        TransportChoice::Tcp { addr, token } => {
            let token = Arc::new(token);
            let c: bus::Connector = Arc::new(move || {
                let token = token.clone();
                Box::pin(async move {
                    let t = TcpTransport::connect(addr, &token).await?;
                    Ok(BusClient::new(Box::new(t)))
                })
            });
            (c, addr.to_string())
        }
        TransportChoice::Fixture(path) => {
            let fixture = match path {
                Some(p) => Fixture::parse(&std::fs::read_to_string(&p)?)?,
                None => Fixture::builtin(),
            };
            let shared = fixture.shared();
            let c: bus::Connector = Arc::new(move || {
                let shared = shared.clone();
                Box::pin(async move { Ok(BusClient::new(Box::new(FixtureTransport::new(shared)))) })
            });
            (c, "fixture".to_string())
        }
        TransportChoice::InProcess(handler) => {
            let c: bus::Connector = Arc::new(move || {
                let h = handler.clone();
                Box::pin(async move { Ok(BusClient::new(Box::new(InProcessTransport::new(h)))) })
            });
            (c, "in-process".to_string())
        }
    })
}

/// Run the interactive UI until the operator quits.
pub async fn run(opts: RunOptions) -> anyhow::Result<()> {
    let caps = opts.caps.unwrap_or_else(TermCaps::detect);
    let theme = Theme::new(caps.truecolor);
    let (connect, label) = connector(opts.transport)?;
    let mut app = App::new(caps, label);

    let (req_tx, req_rx) = mpsc::channel(128);
    let (ev_tx, mut ev_rx) = mpsc::channel(512);
    let bus_task = tokio::spawn(bus::run(connect, req_rx, ev_tx, opts.poll));
    if let Some(note) = opts.startup_note {
        app.toast(Level::Info, note);
    }
    if let Some(listening) = opts.listening {
        app.listening = Some(listening);
    }
    app.poc_dir = opts.poc_dir;

    let mut terminal = ratatui::init();
    let _guard = TerminalGuard { bus_task };
    let size = terminal.size()?;
    let _ = app.update(Action::Resize(size.width, size.height));
    let mut events = EventStream::new();
    let mut tick = tokio::time::interval(Duration::from_millis(250));

    let result: anyhow::Result<()> = loop {
        if let Err(e) = terminal.draw(|f| ui::view(&app, &theme, f)) {
            break Err(e.into());
        }
        let mut requests = Vec::new();
        tokio::select! {
            ev = events.next() => match ev {
                Some(Ok(Event::Key(key))) => {
                    if let Some(action) = keys::map(key, app.mode) {
                        // The copy goes to the terminal first; the app only
                        // reports "copied" when the OSC 52 write succeeded.
                        let failed_copy = if action == Action::CopyUrl && caps.osc52 {
                            app.copy_text()
                                .and_then(|text| clipboard::copy(&text).err())
                        } else {
                            None
                        };
                        match failed_copy {
                            Some(e) => app.toast(Level::Warn, format!("clipboard: {e}")),
                            None => requests.extend(app.update(action)),
                        }
                    }
                }
                Some(Ok(Event::Resize(w, h))) => requests.extend(app.update(Action::Resize(w, h))),
                Some(Ok(Event::Paste(text))) => {
                    for c in text.chars() {
                        requests.extend(app.update(Action::Input(c)));
                    }
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => break Err(e.into()),
                None => break Ok(()),
            },
            Some(event) = ev_rx.recv() => requests.extend(app.on_bus(event)),
            _ = tick.tick() => requests.extend(app.update(Action::Tick)),
        }
        for r in requests {
            if req_tx.send(r).await.is_err() {
                break;
            }
        }
        // `o`: the reducer only names the file; the side effect happens here.
        if let Some(t) = app.take_open_target() {
            match open::open_externally(&t) {
                Ok(()) => app.toast(Level::Info, format!("opened {}", t.label)),
                Err(e) => app.toast(Level::Warn, format!("open: {e}")),
            }
        }
        if app.should_quit {
            break Ok(());
        }
    };
    drop(req_tx);
    // `_guard` restores the terminal and stops the bus task here.
    result
}

/// The 50 commands the bus serves today — `tools/list` of the core as of
/// the 2026-10-28 merge: foundation §4.1's 22, plus `flow.detail` (F5),
/// `flow.mark` / `flow.comment` (F6), `proxy.status` / `proxy.pause` /
/// `proxy.resume` / `flow.clear` / `config.get` (F7), `scope.remove` (F12),
/// `poc.list` / `poc.get` / `poc.artifact` (F13), the M3 Rhai commands
/// `findings.list`, `script.reload`, `script.validate`, and the M6 parity
/// additions — `ws.intercept` / `ws.frame` / `ws.send` (F9), `session.save` /
/// `session.load` / `flow.export` / `flow.import` (F10), `tls.passthrough.*`
/// (F11), `map.add` / `map.list` / `map.remove` (Map). What
/// [`fixture_app_core`] limits the fixture to; `agent.status` / `agent.set`
/// (F1) are the fixture's only tools still ahead of the core.
pub const CORE_TOOLS: &[&str] = &[
    "flow.list",
    "flow.get",
    "flow.detail",
    "flow.intercept",
    "flow.resume",
    "flow.kill",
    "flow.mutate",
    "flow.replay",
    "flow.mark",
    "flow.comment",
    "flow.clear",
    "request.send",
    "scope.add",
    "scope.remove",
    "scope.list",
    "proxy.status",
    "proxy.pause",
    "proxy.resume",
    "config.get",
    "browser.navigate",
    "browser.click",
    "browser.type",
    "browser.screenshot",
    "browser.eval",
    "browser.get_dom",
    "poc.build",
    "poc.run",
    "poc.list",
    "poc.get",
    "poc.artifact",
    "findings.list",
    "script.reload",
    "script.validate",
    "ca.export",
    "ca.status",
    "ca.install",
    "ca.uninstall",
    // M6 parity additions (Task 14 convergence).
    "ws.intercept",
    "ws.frame",
    "ws.send",
    "session.save",
    "session.load",
    "flow.export",
    "flow.import",
    "tls.passthrough.list",
    "tls.passthrough.add",
    "tls.passthrough.remove",
    "map.add",
    "map.list",
    "map.remove",
];

/// An [`App`] loaded synchronously from the built-in fixture, sized `cols`×`rows`,
/// with the paused login request selected — the state every snapshot and UI
/// test starts from. The fixture's whole tool list is offered, F-gated
/// commands included.
pub fn fixture_app(cols: u16, rows: u16) -> App {
    fixture_app_from(Fixture::builtin(), cols, rows)
}

/// [`fixture_app`] against the bus as it exists today: only [`CORE_TOOLS`]
/// are offered. Since the 2026-10-28 core merge that is everything but the
/// F1 agent tools, so the agent toggle and panel show their degraded state
/// and the rest is lit. This is what `aitm-tui --snapshot-core` renders.
pub fn fixture_app_core(cols: u16, rows: u16) -> App {
    load_fixture_app(Fixture::builtin(), cols, rows, true)
}

/// [`fixture_app`] from an already parsed fixture (`--fixture path`): its
/// whole tool list is offered. A fixture is a developer's file, so a tool
/// entry the client cannot read is a panic naming it, not a silent omission.
pub fn fixture_app_from(fx: Fixture, cols: u16, rows: u16) -> App {
    load_fixture_app(fx, cols, rows, false)
}

fn load_fixture_app(mut fx: Fixture, cols: u16, rows: u16, core_only: bool) -> App {
    let mut app = App::new(TermCaps::full(), "fixture");
    let _ = app.update(Action::Resize(cols, rows));
    let tools: Vec<ToolInfo> = fx
        .tools
        .iter()
        .map(|t| {
            ToolInfo::from_json(t).unwrap_or_else(|e| panic!("bus-fixture.json tool entry: {e}"))
        })
        .filter(|t| !core_only || CORE_TOOLS.contains(&t.name.as_str()))
        .collect();
    let _ = app.on_bus(BusEvent::Connected {
        server: format!("{} {}", fx.server_name, fx.server_version),
        tools,
    });
    // The handshake reads `proxy.status` (F7) when the bus has it.
    if app.has_tool("proxy.status") {
        if let Ok(v) = fx.call("proxy.status", &serde_json::Map::new()) {
            let _ = app.on_bus(BusEvent::ProxyStatus(ProxyStatus::from_json(&v)));
        }
    }
    let ids: Vec<String> = fx
        .call("flow.list", &serde_json::Map::new())
        .ok()
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    let arg = |id: &str| -> serde_json::Map<String, Value> {
        let mut m = serde_json::Map::new();
        m.insert("id".into(), Value::String(id.to_string()));
        m
    };
    let summaries: Vec<Value> = ids
        .iter()
        .filter_map(|id| fx.call("flow.get", &arg(id)).ok())
        .collect();
    let _ = app.on_bus(BusEvent::Flows(summaries));
    if app.has_tool("flow.detail") {
        for id in &ids {
            if let Ok(v) = fx.call("flow.detail", &arg(id)) {
                if let Some(d) = FlowDetail::from_json(&v) {
                    let _ = app.on_bus(BusEvent::Detail(Box::new(d)));
                }
            }
        }
    }
    let _ = app.on_bus(BusEvent::Scope(fx.scope.clone()));
    let _ = app.on_bus(BusEvent::Intercept(fx.intercept_armed));
    if app.has_tool("agent.status") {
        let mut agent = AgentState::default();
        agent.apply_status(&fx.agent);
        let _ = app.on_bus(BusEvent::Agent(agent));
    }
    // The PoC library (`poc.list`, files not run), then the recorded run
    // results replayed as `poc.run` answers — oldest first, so the newest
    // ends up on top — then the YAML each asks for through `poc.get`.
    let mut pending = Vec::new();
    if app.has_tool("poc.list") {
        if let Ok(Value::Array(items)) = fx.call("poc.list", &serde_json::Map::new()) {
            let library = items.iter().filter_map(Finding::from_json).collect();
            pending.extend(app.on_bus(BusEvent::Findings(library)));
        }
    }
    if app.has_tool("poc.run") {
        for run in fx.findings.iter().rev() {
            pending.extend(app.on_bus(BusEvent::CallOk {
                name: "poc.run".into(),
                value: run.clone(),
            }));
        }
    }
    for req in pending {
        if let BusRequest::PocGet(path) = req {
            let mut m = serde_json::Map::new();
            m.insert("poc_path".into(), Value::String(path));
            if let Ok(v) = fx.call("poc.get", &m) {
                let _ = app.on_bus(BusEvent::CallOk {
                    name: "poc.get".into(),
                    value: v,
                });
            }
        }
    }
    if app.has_tool("findings.list") {
        if let Ok(v) = fx.call("findings.list", &serde_json::Map::new()) {
            if let Some(items) = v.get("findings").and_then(Value::as_array) {
                let list = items.iter().filter_map(Finding::from_script_json).collect();
                let _ = app.on_bus(BusEvent::ScriptFindings(list));
            }
        }
    }
    // The replay above is a recording, not live events: no toasts from it.
    app.toasts.clear();
    app.selected = Some("f50".into());
    app
}
