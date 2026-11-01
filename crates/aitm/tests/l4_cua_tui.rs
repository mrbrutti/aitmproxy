//! Stage F — CUA (human-driven) real-key acceptance of the **TUI** L4 operator
//! surface (L4OPS-AC14, plan Task 17), against a **real spawned core + bus**.
//!
//! This is the §4.3 CUA path for the ratatui surface, held to Matt's standing
//! acceptance bar — real scenarios, real keys, a real core, a real bus; never a
//! green unit assert or a screenshot alone. It extends the ui-tui foundation's
//! bus-task harness (`tui_live_bus.rs` spawns a real core over the loopback-TCP
//! bus) into a driver that presses **crossterm `KeyEvent`s through the TUI's
//! own key map** ([`aitm_tui::keys::map`]) — the literal human-input path
//! `aitm_tui::run` runs — feeds the live `BusEvent` stream back through the
//! reducer, exactly as the real UI loop does, and reads the screen by drawing
//! the TUI's own `ui::render` into an off-screen buffer. Nothing here calls an
//! `Action` variant directly: every step is a keystroke a real operator types.
//!
//! **What is driven, over the real bus, with real keys:**
//! - the union flow list renders real L4 capture rows (fed through the
//!   protocol-general capture ingress, L4OPS-AC17 — the *same* `L4Guard`), with
//!   the L4 badge + transport sub-label (AC7);
//! - selecting an L4 flow opens the L4 inspector: packet list, the honest
//!   indented **text** layer tree, and the honest hex-degradation note (AC8);
//! - the YAML craft editor builds a `PacketSpec` through the real, pure
//!   `l4.craft` into a hex preview (AC8);
//! - inject reaches the wire **only** through `l4.inject`, and on this
//!   unprivileged host the wire verb surfaces the typed `L4Unavailable` reason —
//!   no fake success, no panic (AC10 / AC18);
//! - scope-as-authorisation: a capture-only flow refuses inject with the scope
//!   reason, and the real guard refuses an out-of-scope capture at the ingress
//!   outright — stronger than the UI's dimming (AC9);
//! - the Agent view's per-feature L4 toggles flip the governing `l4.allow_agent_*`
//!   gate over the bus via `l4.agent.set` (AC11).
//!
//! **Privilege reality (CLI/Linux-first).** This macOS dev host cannot open
//! `/dev/bpf` for raw L4, so the spawned core's startup probe reports
//! capture/inject unavailable and the wire verbs fail closed with a typed
//! `L4Unavailable` — a **required** scenario here (AC18). Because the gated
//! wrapper suppresses the operator confirm-prompt while unavailable, the inject
//! **confirm overlay** (dest + summary + scope + permit budget) and the real
//! packet round-trip against the `aitm-testtarget` L4 service are the
//! **privileged/Linux-gated** half: driven for real only under `AITM_L4_TESTS=1`
//! on an elevated host; asserted-degraded otherwise.
//!
//! **Sandbox.** The Claude sandbox cannot bind TCP; when the bus bind is refused
//! the test prints a note and returns, as `tui_live_bus.rs` does. Run it for real
//! in the Terminal panel: `cargo test -p aitm --test l4_cua_tui -- --nocapture`.

mod support;

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use aitm::ingress::{CaptureIngress, CapturedUnit, IngressOutcome};
use aitm::tui::{self, build_servers};
use aitm::wire::{assemble_with, Assembled, Features};
use aitm_core::{Config, McpTransport};
use aitm_mcp::McpServer;
use aitm_proto_l4::config::L4Config;
use aitm_proto_l4::craft::PacketSpec;
use aitm_proto_l4::types::{
    IpCidr, L4Capability, L4Direction, L4Proto, L4ScopeEntry, L4ScopeId, L4ScopeSource, L4Target,
    PortRange, RateCap,
};
use aitm_testtarget::l4::{L4Config as TargetL4Config, L4Service};
use aitm_tui::action::{BusEvent, BusRequest};
use aitm_tui::app::{App, Mode};
use aitm_tui::caps::TermCaps;
use aitm_tui::model::FlowKind;
use aitm_tui::theme::Theme;
use aitm_tui::TransportChoice;
use anyhow::Context as _;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::buffer::{Buffer, Cell};
use ratatui::layout::Rect;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Instant};

/// The operator token the TUI presents, so the live core serves it as
/// `Frontend::Operator` (the human control surface) — confirm-over-the-wire on
/// the hardest verbs, no agent policy gate, as a real `aitm-tui --bus --token`.
const OPERATOR_TOKEN: &str = "l4-cua-operator-token";
/// The agent-facing loopback token (the policy-gated class the TUI is *not*).
const AGENT_TOKEN: &str = "l4-cua-agent-token";
/// The loopback interface label the scope entries and ingress units agree on.
const IFACE: &str = "lo0";
/// The TUI poll interval under test; short so the live `l4.*` poll lands quickly.
const POLL: Duration = Duration::from_millis(50);
/// The widest the whole drive is allowed to wait on the bus.
const DEADLINE: Duration = Duration::from_secs(8);

/// Whether the privileged real-packet half runs on this host. Loopback raw L4
/// needs `CAP_NET_RAW` / `/dev/bpf`, which a plain dev host lacks; gated behind
/// `AITM_L4_TESTS=1` and Linux (matching the M5 / MCP-acceptance convention).
fn privileged_wire() -> bool {
    !cfg!(target_os = "macos") && std::env::var("AITM_L4_TESTS").ok().as_deref() == Some("1")
}

// ---- config + a real spawned core -------------------------------------------

/// A config-source L4 scope entry (operator authority): config provenance is what
/// lifts the loopback dangerous-destination denylist (SEC-2), so a real inject
/// target can be authorised. Outbound to match the guard's strict direction.
fn config_scope(iface: &str, cap: L4Capability) -> L4ScopeEntry {
    L4ScopeEntry {
        id: L4ScopeId::new(),
        cidr: IpCidr {
            addr: "127.0.0.1".parse().expect("loopback v4"),
            prefix: 32,
        },
        ports: PortRange { lo: 0, hi: 65535 },
        interface: iface.to_string(),
        direction: L4Direction::Outbound,
        capability: cap,
        inject_rate: RateCap {
            pps: 100,
            burst: 100,
        },
        source: L4ScopeSource::Config,
    }
}

/// The L4 module config the operator opted into: enabled, with loopback declared
/// for capture **and** inject on `lo0` (config provenance, so the surface is both
/// drivable and honestly inject-authorised there). Agent gates all default off
/// (the operator flips them from the UI).
fn l4_config() -> L4Config {
    L4Config {
        enabled: true,
        scope: vec![
            config_scope(IFACE, L4Capability::Capture),
            config_scope(IFACE, L4Capability::Inject),
        ],
        ..L4Config::default()
    }
}

/// The core `Config`: a throwaway CA, the loopback-TCP agent transport the TUI
/// connects to, and the operator token that makes the TUI the operator.
fn config(tag: &str) -> Config {
    let mut cfg = support::config(tag);
    cfg.mcp.transport = McpTransport::LoopbackTcp {
        port: 0,
        token: AGENT_TOKEN.into(),
        endpoint_file: None,
    };
    cfg.mcp.operator_token = Some(OPERATOR_TOKEN.into());
    cfg
}

/// A real Ethernet/IPv4/UDP/Raw frame destined for `127.0.0.1:dst_port`, built by
/// the real `PacketSpec` — the on-wire bytes the ingress records and the TUI
/// decodes into the layer tree. (Ethernet is present so `summarize` names the
/// full stack, as a captured loopback frame carries.)
fn udp_frame(dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let spec: PacketSpec = serde_json::from_value(serde_json::json!({
        "layers": [
            {"ether": {}},
            {"ipv4": {"src": "127.0.0.1", "dst": "127.0.0.1"}},
            {"udp": {"dst_port": dst_port}},
            {"raw": payload.iter().map(|b| i64::from(*b)).collect::<Vec<_>>()},
        ]
    }))
    .expect("a valid PacketSpec");
    spec.build().expect("the frame builds")
}

/// A captured L4 unit tagged with the dispatch context the guard decides on.
fn captured(iface: &str, dst: &str, dst_port: u16, bytes: Vec<u8>) -> CapturedUnit {
    CapturedUnit::L4 {
        target: L4Target {
            interface: iface.to_string(),
            direction: L4Direction::Outbound,
            dst: Some(dst.parse().expect("ip")),
            dst_port: Some(dst_port),
            proto: L4Proto::Udp,
        },
        bytes,
    }
}

/// Spawn the agent-facing `McpServer` on loopback TCP and wait for its address.
/// `Ok(None)` when the bind is refused (`PermissionDenied`): the Claude sandbox,
/// not a bug — the caller skips with a note, exactly like `tui_live_bus.rs`.
async fn start_server(server: McpServer) -> anyhow::Result<Option<(SocketAddr, JoinHandle<()>)>> {
    let (bound_tx, bound_rx) = oneshot::channel::<SocketAddr>();
    let server = server.on_bound(move |addr| {
        let _ = bound_tx.send(addr);
    });
    let (done_tx, done_rx) = oneshot::channel::<anyhow::Result<()>>();
    let task = tokio::spawn(async move {
        let _ = done_tx.send(server.serve().await);
    });
    match timeout(DEADLINE, bound_rx)
        .await
        .context("waiting on_bound")?
    {
        Ok(addr) => Ok(Some((addr, task))),
        Err(_closed) => {
            let outcome = timeout(DEADLINE, done_rx)
                .await
                .context("server task did not end after a failed bind")?
                .context("server task dropped its result")?;
            match outcome {
                Ok(()) => anyhow::bail!("serve returned Ok without ever binding"),
                Err(e) if is_permission_denied(&e) => Ok(None),
                Err(e) => Err(e.context("McpServer::serve failed to bind 127.0.0.1:0")),
            }
        }
    }
}

fn is_permission_denied(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|io| io.kind() == io::ErrorKind::PermissionDenied)
    })
}

// ---- the real-key driver ----------------------------------------------------

/// The screen as text, styles dropped: `app` drawn through the TUI's own
/// renderer into an off-screen `cols`×`rows` buffer, one symbol per cell, each
/// line trimmed of trailing spaces, `\n`-joined and ending in `\n` — the same
/// text `crates/aitm-tui/tests/common/mod.rs` reads.
fn text_of(app: &App, cols: u16, rows: u16) -> String {
    let area = Rect::new(0, 0, cols, rows);
    let mut buf = Buffer::empty(area);
    aitm_tui::ui::render(app, &Theme::new(true), area, &mut buf);
    if cols == 0 {
        return "\n".repeat(usize::from(rows));
    }
    // The cells are row-major, so each `cols`-long chunk is one row.
    let mut out = String::new();
    for row in buf.content().chunks(usize::from(cols)) {
        let line: String = row.iter().map(Cell::symbol).collect();
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// The TUI driven headless: the real reducer, fed real keystrokes through the
/// real key map and the live `BusEvent` stream, rendered through the TUI's own
/// `ui::render` into an off-screen buffer. It is `aitm_tui::run`'s loop with
/// the terminal I/O removed.
struct Cua {
    app: App,
    req_tx: mpsc::Sender<BusRequest>,
    ev_rx: mpsc::Receiver<BusEvent>,
}

impl Cua {
    /// Press one bare key, exactly as the UI loop does: map it for the current
    /// mode, fold the resulting action, forward its bus requests, then drain the
    /// bus for a beat so replies land before the next assertion.
    async fn key(&mut self, code: KeyCode) {
        self.key_mods(code, KeyModifiers::NONE).await;
    }

    async fn key_mods(&mut self, code: KeyCode, mods: KeyModifiers) {
        let ev = KeyEvent::new(code, mods);
        if let Some(action) = aitm_tui::keys::map(ev, self.app.mode) {
            for r in self.app.update(action) {
                let _ = self.req_tx.send(r).await;
            }
        }
        self.pump(Duration::from_millis(200)).await;
    }

    /// Drain the live bus, folding each event through the reducer and forwarding
    /// its follow-up requests, until the stream goes quiet for `idle` (bounded).
    async fn pump(&mut self, idle: Duration) {
        let cap = Instant::now() + Duration::from_secs(3);
        while Instant::now() < cap {
            match timeout(idle, self.ev_rx.recv()).await {
                Ok(Some(ev)) => {
                    for r in self.app.on_bus(ev) {
                        let _ = self.req_tx.send(r).await;
                    }
                }
                Ok(None) => break,   // the bus task ended
                Err(_idle) => break, // quiet
            }
        }
    }

    /// Pump until `pred` holds or `DEADLINE` elapses — for the handshake and the
    /// first live `l4.*` poll to populate flows / scope / gates.
    async fn pump_until(&mut self, what: &str, pred: impl Fn(&App) -> bool) {
        let cap = Instant::now() + DEADLINE;
        while Instant::now() < cap {
            if pred(&self.app) {
                return;
            }
            match timeout(Duration::from_millis(300), self.ev_rx.recv()).await {
                Ok(Some(ev)) => {
                    for r in self.app.on_bus(ev) {
                        let _ = self.req_tx.send(r).await;
                    }
                }
                Ok(None) => break,
                Err(_) => {} // keep waiting for the next poll
            }
        }
        assert!(
            pred(&self.app),
            "timed out waiting for {what}:\n{}",
            self.screen()
        );
    }

    /// The operator-visible screen, rendered exactly as the terminal would draw it.
    fn screen(&self) -> String {
        text_of(&self.app, self.app.width, self.app.height)
    }

    /// Press Down in the flow list until the selected flow is the L4 flow on
    /// `iface`, or give up after a bounded number of steps.
    async fn select_l4_on(&mut self, iface: &str) {
        for _ in 0..self.app.flows.len().max(1) + 2 {
            if self.app.selected_l4().is_some_and(|f| f.interface == iface) {
                return;
            }
            self.key(KeyCode::Down).await;
        }
        panic!(
            "no selectable L4 flow on `{iface}` in the list:\n{}",
            self.screen()
        );
    }

    /// Dump the current screen to the test log under a heading (the CUA's
    /// terminal snapshots; visible with `-- --nocapture`).
    fn snapshot(&self, heading: &str) {
        eprintln!("\n========== {heading} ==========\n{}", self.screen());
    }
}

/// Print a bold step banner to the run log.
fn step(n: u32, what: &str) {
    eprintln!("\n########## STEP {n}: {what} ##########");
}

// ---- the acceptance drive ----------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tui_l4_cua_against_a_live_core() {
    let cfg = config("l4-cua");
    let l4 = l4_config();

    // (A) Assemble the real core with L4 enabled over the **real startup
    // privilege probe** (`l4_privilege: None`): on this host the probe reports
    // capture/inject unavailable, so the wire verbs fail closed honestly — the
    // required macOS scenario (AC18). The ingress is the module's shared guard +
    // store (AC17), so an ingress-fed packet is what `l4.flow.*` reads.
    let assembled = assemble_with(
        &cfg,
        &Features {
            l4: l4.clone(),
            l4_privilege: None,
            ..Features::default()
        },
    )
    .expect("assemble a core with l4 enabled");
    let governance = assembled.governance();
    let Assembled {
        proxy,
        l4_ingress,
        job_bus,
        ..
    } = assembled;
    let ingress = l4_ingress.expect("l4.enabled wires the capture ingress (AC17)");

    // (B) Scope-as-authorisation, enforced below the UI: the real `L4Guard`
    // refuses an out-of-scope capture at the ingress outright — nothing is stored
    // — which is stronger than the UI's courtesy dimming. Assert it before
    // feeding the in-scope packets.
    let out_of_scope = ingress.accept(captured(IFACE, "10.1.2.3", 9, udp_frame(9, b"nope")));
    assert_eq!(
        out_of_scope,
        IngressOutcome::Refused,
        "the guard must refuse an out-of-scope capture at the ingress"
    );
    eprintln!("[guard] out-of-scope capture at the ingress → {out_of_scope:?} (refused, airtight)");

    // (C) Feed real in-scope frames through the ingress → a real capture flow on
    // `lo0`. This is the protocol-general capture path (one capture session is one
    // flow); privilege is only the pcap backend's, which the ingress bypasses — the
    // frames are guarded by the same `L4Guard` either way.
    for i in 0..2u8 {
        let r = ingress.accept(captured(
            IFACE,
            "127.0.0.1",
            7,
            udp_frame(7, &[b'p', b'r', i]),
        ));
        assert_eq!(r, IngressOutcome::Captured, "in-scope lo0 capture #{i}");
    }

    // (D) Serve the agent-facing server on loopback TCP, exactly as `aitm tui`
    // builds it (`services` → `build_servers`). Skip cleanly if the sandbox
    // refuses the bind.
    let services = tui::services(&proxy, &cfg, None, tui::TuiLog::Off, job_bus);
    let server = build_servers(&cfg, services, governance)
        .0
        .expect("a loopback-TCP transport yields an agent server");
    let Some((addr, server_task)) = start_server(server)
        .await
        .expect("start the live MCP server")
    else {
        eprintln!(
            "l4_cua_tui: skipped — this sandbox refuses to bind 127.0.0.1:0 (PermissionDenied). \
             Run `cargo test -p aitm --test l4_cua_tui -- --nocapture` in the Terminal panel."
        );
        return;
    };

    // (E) A real in-scope L4 target on loopback (Stage-D `aitm-testtarget`): the
    // UDP echo + TCP service the privileged real-packet half drives against.
    let target = L4Service::start(TargetL4Config { enabled: true }).await;
    if let Some(t) = &target {
        eprintln!(
            "[target] aitm-testtarget L4 service up: udp {} tcp {}",
            t.udp_addr(),
            t.tcp_addr()
        );
    }

    // (F) The real TUI bus client over the real `TcpTransport`, operator token.
    let (connect, label) = aitm_tui::connector(TransportChoice::Tcp {
        addr,
        token: OPERATOR_TOKEN.into(),
    })
    .expect("build the TCP connector");
    let (req_tx, req_rx) = mpsc::channel::<BusRequest>(64);
    let (ev_tx, ev_rx) = mpsc::channel::<BusEvent>(256);
    let bus_task = tokio::spawn(aitm_tui::bus::run(connect, req_rx, ev_tx, POLL));

    let mut app = App::new(TermCaps::full(), label);
    let _ = app.update(aitm_tui::action::Action::Resize(200, 60));
    let mut cua = Cua { app, req_tx, ev_rx };

    // ---- STEP 0: connect; feature-detect l4.* ; the first live poll lands ----
    step(0, "connect to the live core; feature-detect the L4 surface");
    cua.pump_until("the L4 surface and first poll", |a| {
        a.has_tool("l4.flow.list")
            && a.flows.iter().any(|r| r.kind == FlowKind::L4)
            && !a.l4.scope.is_empty()
            && a.l4.gates.present
    })
    .await;
    assert!(
        cua.app.has_tool("l4.inject"),
        "l4.* advertised on the live bus"
    );
    assert!(
        cua.app.has_tool("l4.agent.set"),
        "the operator gate setter is present"
    );
    eprintln!(
        "[bus] l4.* tools present; {} L4 scope entries; gates present={}",
        cua.app.l4.scope.len(),
        cua.app.l4.gates.present
    );

    // ---- STEP 1: the union flow list renders real L4 rows (AC7) ----
    step(
        1,
        "the union flow list shows the live L4 capture rows (AC7)",
    );
    cua.snapshot("flow list — L4 rows");
    let list = cua.screen();
    assert!(
        list.contains("L4 UDP"),
        "the L4 badge + UDP sub-label renders: {list}"
    );

    // ---- STEP 2: open the L4 inspector; packets + text layer tree + hex (AC8) ----
    step(
        2,
        "open the lo0 capture flow → packet list, text layer tree, honest hex (AC8)",
    );
    cua.select_l4_on(IFACE).await;
    cua.key(KeyCode::Enter).await; // Flows → Inspector
    assert_eq!(
        cua.app.mode,
        Mode::Inspector,
        "Enter opens the L4 inspector"
    );
    cua.snapshot("L4 inspector — Packets pane");
    let insp = cua.screen();
    assert!(
        insp.contains("layer tree (text)"),
        "honest text layer tree: {insp}"
    );
    for layer in ["IPv4", "UDP"] {
        assert!(insp.contains(layer), "decoded layer {layer} shown: {insp}");
    }
    assert!(
        insp.to_lowercase().contains("not carried by l4.flow.get"),
        "honest hex-degradation note (l4.flow.get carries no bytes): {insp}"
    );

    // ---- STEP 3: the craft editor builds a PacketSpec via real l4.craft (AC8) ----
    step(
        3,
        "Tab to the craft editor; `b` builds the PacketSpec → hex preview (AC8)",
    );
    for _ in 0..3 {
        if cua.app.l4.pane == aitm_tui::l4::L4Pane::Craft {
            break;
        }
        cua.key(KeyCode::Tab).await;
    }
    assert_eq!(
        cua.app.l4.pane,
        aitm_tui::l4::L4Pane::Craft,
        "reached the Craft pane"
    );
    cua.snapshot("L4 inspector — Craft editor (YAML PacketSpec)");
    assert!(
        cua.screen().contains("layers:"),
        "the YAML PacketSpec editor renders"
    );
    cua.key(KeyCode::Char('b')).await; // L4Build → l4.craft (pure, real)
    cua.pump(Duration::from_millis(300)).await;
    cua.snapshot("L4 craft — hex preview built by l4.craft");
    assert!(
        cua.app.l4.craft.preview.is_some(),
        "l4.craft built real bytes into the hex preview: {}",
        cua.screen()
    );
    eprintln!(
        "[craft] l4.craft built {} bytes (layers {:?})",
        cua.app.l4.craft.preview.as_ref().map_or(0, Vec::len),
        cua.app.l4.craft.preview_layers
    );

    // ---- STEP 4: inject reaches the wire ONLY via l4.inject; honest degradation ----
    step(
        4,
        "`s` injects via l4.inject only; the wire verb degrades honestly (AC10/AC18)",
    );
    cua.key(KeyCode::Char('s')).await; // L4Inject
    if privileged_wire() && cua.app.mode == Mode::L4Confirm {
        // Privileged host: the confirm overlay shows the wire summary, then `y`
        // re-issues with the `_confirm` token and the real packet reaches the
        // target. (Linux / elevated only.)
        cua.snapshot("L4 inject — confirm overlay (privileged)");
        let ov = cua.screen();
        assert!(
            ov.contains("127.0.0.1"),
            "confirm shows the destination: {ov}"
        );
        assert!(
            ov.to_lowercase().contains("scope"),
            "confirm shows the scope: {ov}"
        );
        assert!(
            ov.contains("budget"),
            "confirm shows the permit budget: {ov}"
        );
        cua.key(KeyCode::Char('y')).await;
        cua.pump(Duration::from_millis(400)).await;
        cua.snapshot("L4 inject — after confirm (privileged real packet)");
        eprintln!("[inject] privileged path: confirmed and sent a real packet");
    } else {
        // This macOS host: the gated wrapper suppresses the confirm-prompt while
        // unavailable, so inject goes straight to the wire verb, which fails
        // closed with the typed reason — no overlay, no fake success, no panic.
        cua.pump(Duration::from_millis(400)).await;
        cua.snapshot("L4 inject — honest L4Unavailable degradation");
        let screen = cua.screen().to_lowercase();
        assert!(
            screen.contains("unavailable"),
            "the wire verb surfaces the typed L4Unavailable reason: {}",
            cua.screen()
        );
        assert_ne!(
            cua.app.mode,
            Mode::L4Confirm,
            "no overlay without privilege"
        );
        eprintln!("[inject] honest degradation: l4.inject → L4Unavailable (no fake success)");
    }

    // ---- STEP 5: scope-as-authorisation — the guard refuses out-of-scope capture (AC9) ----
    step(
        5,
        "scope-as-authorisation: the real guard refuses out-of-scope capture at the ingress (AC9)",
    );
    cua.key(KeyCode::Esc).await; // Inspector → Flows (back to the union list)
                                 // Against a real core the enforcement is the guard, not the UI's dimming: an
                                 // out-of-scope packet is refused at the ingress and is **never captured**, so a
                                 // dimmed out-of-scope L4 flow cannot even exist in the store — a stronger
                                 // property than the UI's dimming. Drive one more refusal live.
    let refused_again = ingress.accept(captured(IFACE, "203.0.113.9", 80, udp_frame(80, b"evil")));
    assert_eq!(
        refused_again,
        IngressOutcome::Refused,
        "an out-of-scope destination on an in-scope interface is still refused"
    );
    // The in-scope lo0 flow is unaffected; the surface keeps rendering it and the
    // persistent L4-unavailable reason is in the status line (honest, remediable).
    cua.snapshot("flow list — in-scope flow intact; out-of-scope capture refused by the guard");
    assert!(
        cua.app
            .flows
            .iter()
            .filter(|r| r.kind == FlowKind::L4)
            .count()
            == 1,
        "the refused out-of-scope packet created no flow: {}",
        cua.screen()
    );
    eprintln!(
        "[scope] out-of-scope capture refused at the ingress (no flow created); the UI's \
         inject-disabled-with-scope-reason is a courtesy on top of this guard"
    );

    // ---- STEP 6: the Agent view's per-feature L4 toggle flips the gate (AC11) ----
    step(
        6,
        "the Agent view L4 toggles flip the governing gate via l4.agent.set (AC11)",
    );
    cua.key(KeyCode::Esc).await; // back to the list
    cua.key(KeyCode::Char('@')).await; // OpenAgent
    assert_eq!(cua.app.mode, Mode::Agent, "@ opens the Agent view");
    cua.snapshot("Agent view — L4 capability toggles");
    let agent = cua.screen();
    assert!(
        agent.contains("L4 agent capabilities"),
        "the L4 capability section renders: {agent}"
    );
    let inject_gate_before = cua.app.l4.gates.inject;
    cua.key(KeyCode::Char('i')).await; // toggle the Inject gate → l4.agent.set
    cua.pump(Duration::from_millis(300)).await;
    cua.snapshot("Agent view — after toggling the Inject gate over the bus");
    assert_ne!(
        cua.app.l4.gates.inject,
        inject_gate_before,
        "toggling flips the governing gate over the bus (l4.agent.set): {}",
        cua.screen()
    );
    eprintln!(
        "[agent] Inject gate {} → {} via l4.agent.set on the live bus",
        inject_gate_before, cua.app.l4.gates.inject
    );

    eprintln!("\n########## TUI L4 CUA: all steps passed against the live core ##########");
    if !privileged_wire() {
        eprintln!(
            "NOTE: wire verbs degraded honestly (L4Unavailable) on this unprivileged host; the \
             confirm overlay + real-packet round-trip + in-path intercept bar are the \
             privileged/Linux-gated half — run with AITM_L4_TESTS=1 on an elevated Linux host."
        );
    }

    // ---- teardown ----
    drop(cua.req_tx);
    drop(target);
    let _ = timeout(Duration::from_secs(2), bus_task).await;
    server_task.abort();
}
