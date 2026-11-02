//! `aitm-tui` — aitmproxy's terminal operator UI (foundation §2.10(c)).
//!
//! A ratatui client of the command bus: the same flow list, inspector,
//! intercept bar, compose, scope, PoC and agent surfaces as the macOS and web
//! apps, drawn with the shared tokens and degraded the way §2.9 spells out.
//! It talks to the proxy through [`aitm_bus_client`] over loopback TCP, or
//! over an in-process handler when `aitm tui` embeds the proxy.
//!
//! Structure: [`app`] holds the state and reducer, [`bus`] the one task that
//! talks to the proxy, [`ui`] and [`viewers`] draw, [`open`] hands a file to
//! the desktop for `o`.

pub mod action;
pub mod app;
pub mod base64;
pub mod bus;
pub mod caps;
pub mod clipboard;
pub mod filter;
pub mod keys;
pub mod l4;
pub mod languages;
pub mod model;
pub mod open;
pub mod syntax;
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
use tokio::sync::mpsc;

use crate::action::{Action, Level};
use crate::app::App;
use crate::caps::TermCaps;
use crate::theme::Theme;

/// Where the UI gets its bus.
pub enum TransportChoice {
    /// A running proxy's loopback TCP transport.
    Tcp { addr: SocketAddr, token: String },
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
    /// The role the operator expects the token to resolve to (`--expect-role`):
    /// client-side only, it drives the status line's mismatch warning and is
    /// never sent to the server. `None` means no expectation.
    pub expect_role: Option<String>,
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
    app.expect_role = opts.expect_role;

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

/// The commands the bus serves today — `tools/list` of the core as of
/// the 2026-10-29 M4 merge: foundation §4.1's 22, plus `flow.detail` (F5),
/// `flow.mark` / `flow.comment` (F6), `proxy.status` / `proxy.pause` /
/// `proxy.resume` / `flow.clear` / `config.get` (F7), `scope.remove` (F12),
/// `poc.list` / `poc.get` / `poc.artifact` (F13), the M3 Rhai commands
/// `findings.list`, `script.reload`, `script.validate`, the M6 parity
/// additions — `ws.intercept` / `ws.frame` / `ws.send` (F9), `session.save` /
/// `session.load` / `flow.export` / `flow.import` (F10), `tls.passthrough.*`
/// (F11), `map.add` / `map.list` / `map.remove` (Map) — and the M4 additions:
/// `agent.status` / `agent.set` / `agent.activity` / `agent.approve` (F1) and
/// `flow.subscribe` / `flow.unsubscribe` (F4). `crates/aitm/tests/tui_live_bus.rs`
/// pins this list against the running server's `tools/list`.
pub const CORE_TOOLS: &[&str] = &[
    "flow.list",
    "flow.get",
    "flow.table",
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
    // capture.status (spec 2026-10-31-capture-status-verb-design): the macOS NE
    // capture feeder's read-only state (Sensitivity::Read), registered on every
    // platform.
    "capture.status",
    // proxy.system.* (spec 2026-10-31-system-proxy-automation-design): the OS
    // system proxy read (Sensitivity::Read) and the two operator-only mutators
    // (Sensitivity::Sensitive), registered on every platform.
    "proxy.system.status",
    "proxy.system.set",
    "proxy.system.unset",
    "browser.navigate",
    "browser.click",
    "browser.type",
    "browser.screenshot",
    "browser.eval",
    "browser.get_dom",
    "browser.confine",
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
    // M4 additions: F1 agent control and F4 flow subscription, now core.
    "agent.status",
    "agent.set",
    "agent.activity",
    "agent.approve",
    "flow.subscribe",
    "flow.unsubscribe",
    // Scanner plugin (Stage 1): read-only crawl + injection-point discovery.
    "scan.discover",
    // Scanner plugin (Stage 2): passive checks over captured flows (Read).
    "scan.passive",
    // Scanner plugin (Stage 2): findings report + index over recorded findings (Read).
    "scan.report",
    // Scanner v2 (spec 2026-10-31-aitmproxy-scanner-v2-design, D3): the job verb
    // family. `scan.start` is Sensitive; `scan.map`, `scan.cancel` and the profile
    // mutators are Write; the rest are Read.
    "scan.start",
    "scan.map",
    "scan.status",
    "scan.list",
    "scan.cancel",
    "scan.issues",
    "scan.issue",
    "scan.issue.update",
    "scan.sitemap",
    "scan.checks",
    "scan.profile.list",
    "scan.profile.get",
    "scan.profile.save",
    "scan.profile.delete",
    "scan.session.preview",
    // One manual verb per registered check (D3 `check.<id>`): the interim HTTP
    // lane's two active checks and three passive checks. The three interim
    // passive ids go away with T2's integration.
    "check.xss-reflected",
    "check.open-redirect",
    "check.reflection",
    "check.security-header",
    "check.cookie-flag",
    // The T4 WS lane's eight checks (`aitm-scan-ws`), each with its `check.<id>`
    // manual verb.
    "check.cswsh",
    "check.ws-auth-bypass-handshake",
    "check.ws-cmdi-echo",
    "check.ws-input-reflection",
    "check.ws-oversize-frame",
    "check.ws-sql-error",
    "check.ws-ssti",
    "check.ws-subprotocol-observe",
    "check.l4-packet-crash",
    "check.l4-packet-reaction",
];

/// An [`App`] for in-crate tests: `cols`×`rows`, connected to a bus that
/// offers every [`CORE_TOOLS`] name. Flows, details and findings are not
/// part of it; each test feeds the `BusEvent`s it needs as inline literals.
#[cfg(test)]
pub(crate) fn connected_app(cols: u16, rows: u16) -> App {
    use crate::action::{BusEvent, ToolInfo};

    let mut app = App::new(TermCaps::full(), "test");
    let _ = app.update(Action::Resize(cols, rows));
    let tools = CORE_TOOLS
        .iter()
        .map(|name| ToolInfo {
            name: (*name).to_string(),
            description: format!("{name} (test)"),
            input_schema: serde_json::json!({"type": "object", "properties": {}}),
            confirmable: false,
        })
        .collect();
    let _ = app.on_bus(BusEvent::Connected {
        server: "aitmproxy test".into(),
        tools,
        role: None,
    });
    app
}

/// A `flow.get` summary in the core's wire shape, for in-crate tests: the
/// one builder the `app`, `ui` and `ui::flows` test modules share.
#[cfg(test)]
pub(crate) fn summary(
    id: &str,
    method: &str,
    authority: &str,
    path: &str,
    status: Option<u16>,
    intercept: &str,
) -> serde_json::Value {
    serde_json::json!({
        "id": id, "kind": "http", "method": method, "scheme": "https",
        "authority": authority, "path": path, "status": status,
        "is_replay": false, "intercept": intercept,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tester (D7): the in-crate test bus offers every `CORE_TOOLS` name
    /// exactly once and nothing more; its address `test` is not loopback
    /// (so a screenshot goes through `poc.artifact`, never the local disk);
    /// it is the size asked for; and it carries no flows, details, scope or
    /// findings — every test writes those itself.
    #[test]
    fn connected_app_offers_every_core_tool_and_nothing_else() {
        let app = connected_app(120, 30);
        assert_eq!(app.tools.len(), CORE_TOOLS.len());
        for name in CORE_TOOLS {
            assert!(app.has_tool(name), "{name} is on the test bus");
            assert_eq!(
                app.tools.iter().filter(|t| t.name == *name).count(),
                1,
                "{name} listed once"
            );
        }
        assert!(!app.is_loopback_bus());
        assert_eq!((app.width, app.height), (120, 30));
        assert!(app.flows.is_empty());
        assert!(app.details.is_empty());
        assert!(app.scope.is_empty());
        assert!(app.findings.is_empty());
        assert_eq!(app.selected, None);
    }
}
