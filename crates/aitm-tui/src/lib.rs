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
//! off-screen, [`fixture`] serves the recorded bus.

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
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::action::{Action, BusEvent, ToolInfo};
use crate::app::App;
use crate::caps::TermCaps;
use crate::fixture::{Fixture, FixtureTransport};
use crate::model::{AgentState, Finding, FlowDetail};
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
    /// otherwise it comes from `proxy.status` (core follow-up F7) or stays unknown.
    pub listening: Option<String>,
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
        app.toast(action::Level::Info, note);
    }
    if opts.listening.is_some() {
        app.listening = opts.listening;
    }

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
                        if action == Action::CopyUrl && caps.osc52 {
                            if let Some(text) = app.copy_text() {
                                let _ = clipboard::copy(&text);
                            }
                        }
                        requests.extend(app.update(action));
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
        if app.should_quit {
            break Ok(());
        }
    };
    drop(req_tx);
    // `_guard` restores the terminal and stops the bus task here.
    result
}

/// An [`App`] loaded synchronously from the built-in fixture, sized `cols`×`rows`,
/// with the paused login request selected — the state every snapshot and UI
/// test starts from.
pub fn fixture_app(cols: u16, rows: u16) -> App {
    let mut fx = Fixture::builtin();
    let mut app = App::new(TermCaps::full(), "fixture");
    let _ = app.update(Action::Resize(cols, rows));
    let tools = fx
        .tools
        .iter()
        .map(|t| ToolInfo {
            name: t["name"].as_str().unwrap_or("").to_string(),
            description: t["description"].as_str().unwrap_or("").to_string(),
            input_schema: t.get("inputSchema").cloned().unwrap_or(Value::Null),
        })
        .collect();
    let listening = Some(fx.listening.clone());
    let _ = app.on_bus(BusEvent::Connected {
        server: format!("{} {}", fx.server_name, fx.server_version),
        tools,
        listening,
    });
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
    for id in &ids {
        if let Ok(v) = fx.call("flow.detail", &arg(id)) {
            if let Some(d) = FlowDetail::from_json(&v) {
                let _ = app.on_bus(BusEvent::Detail(Box::new(d)));
            }
        }
    }
    let _ = app.on_bus(BusEvent::Scope(fx.scope.clone()));
    let _ = app.on_bus(BusEvent::Intercept(fx.intercept_armed));
    let mut agent = AgentState::default();
    agent.apply_status(&fx.agent);
    let _ = app.on_bus(BusEvent::Agent(agent));
    let findings = fx.findings.iter().filter_map(Finding::from_json).collect();
    let _ = app.on_bus(BusEvent::Findings(findings));
    app.selected = Some("f50".into());
    let _ = json!({});
    app
}
