import AitmproxyKit
import SwiftUI

/// The window toolbar (foundation §2.7 "Toolbar"; spec 2026-10-31 status page §4): compose,
/// clear · the connection cluster — pill, Proxy switch, Capture switch — · the Agent toggle,
/// palette, layout. The cluster is the ONE home of connection state: the sidebar's brand row
/// and the status bar carry none (`tools/check-connection-words.sh` pins it).
struct ShellToolbar: ToolbarContent {
    @Environment(Session.self) private var session
    @Binding var sidebarVisible: Bool

    var body: some ToolbarContent {
        ToolbarItemGroup(placement: .navigation) {
            Button { sidebarVisible.toggle() } label: {
                Label("Toggle Sidebar", systemImage: Tok.Glyph.sidebar)
            }
            .help(sidebarVisible ? "Hide the sidebar (⌃⌘S)" : "Show the sidebar (⌃⌘S)")
            Button { session.openCompose() } label: { Label("Compose", systemImage: Tok.Glyph.compose) }
                .help("Compose a request (⌘N)")
            Button { session.clearSession(confirm: ClearConfirmation.ask) } label: { Label("Clear Session", systemImage: Tok.Glyph.clear) }
                .help("Clear every flow from the session (⌘⌫)")
        }
        .sharedBackgroundVisibility(.hidden)
        ToolbarItem(placement: .principal) {
            ConnectionCluster()
        }
        .sharedBackgroundVisibility(.hidden)
        ToolbarItemGroup(placement: .primaryAction) {
            AgentToggle()
            Button {
                session.paletteOpenedByKeyboard = false
                session.paletteVisible.toggle()
            } label: { Label("Command Palette", systemImage: Tok.Glyph.palette) }
                .help("Command palette (⌘K)")
            LayoutPicker()
        }
        .sharedBackgroundVisibility(.hidden)
    }
}

/// `● aitmproxy · 127.0.0.1:8080  Proxy [●━]  Capture [━●]`: the three connection lanes and
/// the two switches that change them, in the words the Status page uses. One
/// `connectionSummary` read feeds the whole cluster.
struct ConnectionCluster: View {
    @Environment(Session.self) private var session

    var body: some View {
        let summary = session.connectionSummary
        HStack(spacing: Space.sm) {
            ListeningPill(summary: summary)
            ProxySwitch(summary: summary)
            CaptureExtensionSwitch(summary: summary)
        }
    }
}

/// The pill: core dot + bound address, calm (dot only) while the bus and capture lanes are
/// fine, worded when one needs attention. Clicking opens the Status page; drawn on `active`
/// while Status is showing, so the page has a selected entry without being a sidebar row.
struct ListeningPill: View {
    @Environment(Session.self) private var session
    var summary: ConnectionSummary

    var body: some View {
        let selected = session.page == .status
        Button { session.show(.status) } label: {
            HStack(spacing: Space.sm) {
                HStack(spacing: Tok.Metric.gapTight) {
                    Circle().fill(summary.core.state.color.color).frame(width: Tok.Size.statusDot, height: Tok.Size.statusDot)
                    Text("aitmproxy").fontWeight(.medium).foregroundStyle(Tok.Ink.primary.color)
                    if summary.core.state == .ok {
                        Text(session.capturing ? " · " : " · paused ")
                        Text(session.coreHealth.connection?.proxyAddress ?? session.listenAddress)
                            .font(Tok.Face.data(Tok.Typography.Size.sm, .medium))
                            .foregroundStyle(Tok.Ink.primary.color)
                        if session.interceptArmed { Text(" · intercept armed") }
                    } else {
                        Text(" · core \(summary.core.word)")
                    }
                }
                LaneDot(lane: summary.bus, quietWhenOK: true)
                LaneDot(lane: summary.capture, quietWhenOK: true)
            }
            .font(Tok.Face.ui(Tok.Typography.Size.sm))
            .foregroundStyle(Tok.Ink.secondary.color)
            .lineLimit(1)
            .padding(.leading, Tok.Metric.padInner)
            .padding(.trailing, Space.md)
            .frame(height: Tok.Size.control)
            .background(selected ? Tok.Ground.active.color : Tok.Ground.raised.color, in: Capsule())
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .help(summary.tooltip + "\nOpens Status (⌘0)")
        .accessibilityElement(children: .combine)
        .accessibilityLabel("aitmproxy: \(summary.spoken)")
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

/// On = the proxy records flows; off = paused (`proxy.pause`: traffic still passes, new flows
/// are not recorded). The same entry as View ▸ Pause Proxy / Resume Proxy (⇧⌘R) and the
/// palette. Live while the bus is connected — pause is a bus call, whichever core answers.
struct ProxySwitch: View {
    @Environment(Session.self) private var session
    var summary: ConnectionSummary

    var body: some View {
        let live = ToolbarSwitches.proxyLive(summary)
        ToolbarSwitch(
            title: "Proxy", on: live && session.capturing, tint: Tok.Status.success.color, enabled: live,
            help: ToolbarSwitches.proxyHelp(summary, capturing: session.capturing)
        ) { session.setCapturing(!session.capturing) }
    }
}

/// The capture extension's switch. Its position is the published fact, not the preference
/// (spec §1): on whenever the capture lane is doing anything — capturing, waiting for approval,
/// degraded — off when the lane is off; `captureChoice` carries it through a switch in flight.
/// Its colour is the lane's state, so "on, nothing in scope" shows the warning hue and
/// "waiting for approval" the working hue. Flips through `CaptureSwitch.set` — the same steps as Settings ▸
/// Capture, Proxy ▸ Turn On / Turn Off Capture (⌃⌘C) and the Status card. Operator-only:
/// reached by a click here and nowhere else (`tools/check-capture-operator-only.sh` lists this
/// file beside those three).
struct CaptureExtensionSwitch: View {
    @Environment(Session.self) private var session
    var summary: ConnectionSummary

    var body: some View {
        let health = session.coreHealth
        let embedded = (session.connection?.activeKind ?? .embedded) == .embedded
        let on = health.captureChoice ?? ToolbarSwitches.captureOn(summary.capture)
        ToolbarSwitch(
            title: "Capture", on: on, tint: summary.capture.state.color.color,
            enabled: ToolbarSwitches.captureLive(health, embedded: embedded),
            help: ToolbarSwitches.captureHelp(summary.capture, controlsAvailable: health.captureControlsAvailable,
                                              embedded: embedded, busy: health.captureBusy, choice: on)
        ) { Task { await CaptureSwitch.set(!on, session: session) } }
    }
}

/// The switches' enabled rules and help text as plain functions, so the self-test can pin
/// them (ST-AC9) without a view.
enum ToolbarSwitches {
    /// Pause/resume is a bus call: live while the bus is connected (as operator or as agent).
    static func proxyLive(_ summary: ConnectionSummary) -> Bool {
        summary.bus.state == .ok || summary.bus.state == .warning
    }

    static func proxyHelp(_ summary: ConnectionSummary, capturing: Bool) -> String {
        guard proxyLive(summary) else { return "Bus \(summary.bus.word) — connect to pause or resume the proxy" }
        return capturing
            ? "Pause the proxy: traffic still passes and new flows are not recorded (⇧⌘R)"
            : "Resume recording flows (⇧⌘R)"
    }

    /// The switch's resting position: the extension is on unless its lane is off.
    static func captureOn(_ lane: ConnectionLane) -> Bool { lane.state != .off }

    /// The same gate as Settings ▸ Capture's toggle and Proxy ▸ Turn On / Turn Off Capture.
    static func captureLive(_ health: CoreHealthState, embedded: Bool) -> Bool {
        health.captureControlsAvailable && !health.captureBusy && embedded
    }

    static func captureHelp(_ lane: ConnectionLane, controlsAvailable: Bool, embedded: Bool, busy: Bool,
                            choice: Bool) -> String {
        if busy { return "Switching the capture extension…" }
        if !controlsAvailable { return "The capture extension is not in this build" }
        if !embedded { return "The active core is external — switch to the embedded core in Settings ▸ Bus to control capture" }
        var lines = [choice
            ? "Turn off the capture extension (⌃⌘C)"
            : "Turn on the capture extension: it captures other apps' traffic without proxy settings (⌃⌘C)"]
        lines.append("\(lane.compact) — \(lane.detail)")
        if let remedy = lane.remedy { lines.append(remedy) }
        return lines.joined(separator: "\n")
    }
}

/// A word and a small switch: the toolbar's control for one on/off thing. A real `Toggle` under
/// a custom style, so VoiceOver gets a checkbox titled "Proxy" / "Capture" with an on/off value
/// and AXPress flips it (a plain `Button` here exposed an untitled "toggle button" and swallowed
/// System Events clicks — found live, 2026-10-31). The track takes its owner's colour when on
/// (a lane's state colour, the agent teal) and tertiary when off; disabled drops the word to
/// tertiary and says why in `help`.
struct ToolbarSwitch: View {
    var title: String
    var on: Bool
    var tint: Color
    var enabled = true
    var help: String
    var action: () -> Void

    var body: some View {
        Toggle(title, isOn: Binding(get: { on }, set: { _ in action() }))
            .toggleStyle(ToolbarSwitchStyle(tint: enabled ? tint : Tok.Ink.tertiary.color, enabled: enabled))
            .disabled(!enabled)
            .help(help)
    }
}

/// Draws a `Toggle` as `[●━] Word`: the shared `SwitchGlyph` and the title in ink (tertiary when
/// disabled). Tapping anywhere on it flips the binding.
struct ToolbarSwitchStyle: ToggleStyle {
    var tint: Color
    var enabled: Bool

    func makeBody(configuration: Configuration) -> some View {
        Button { configuration.isOn.toggle() } label: {
            HStack(spacing: Space.sm) {
                SwitchGlyph(on: configuration.isOn, tint: tint)
                configuration.label
                    .font(Tok.Face.ui(Tok.Typography.Size.sm))
                    .foregroundStyle(enabled ? Tok.Ink.primary.color : Tok.Ink.tertiary.color)
            }
            .padding(.horizontal, Space.sm)
            .frame(height: Tok.Size.control)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

/// The 26 × 16 track and 12 pt knob every toolbar switch shares (Proxy, Capture, Agent).
struct SwitchGlyph: View {
    var on: Bool
    var tint: Color

    var body: some View {
        Capsule()
            .fill(on ? tint : Tok.Ink.tertiary.color)
            .frame(width: Tok.Metric.switchWidth, height: Tok.Metric.switchHeight)
            .overlay(alignment: on ? .trailing : .leading) {
                Circle().fill(.white).frame(width: Tok.Metric.switchKnob, height: Tok.Metric.switchKnob).padding(2)
            }
            .accessibilityHidden(true)
    }
}

/// `[Agent ●]` teal when the agent may act, grey when paused; a count of
/// agent actions in the last minute. Click → policy menu (F1).
struct AgentToggle: View {
    @Environment(Session.self) private var session

    var body: some View {
        @Bindable var session = session
        Menu {
            Picker("Agent policy", selection: Binding(get: { session.agentPolicy }, set: { session.activity.choose($0) })) {
                ForEach(AgentPolicy.allCases, id: \.self) { Text($0.title).tag($0) }
            }
            .pickerStyle(.inline)
            Divider()
            Button("Activity Log…") { session.activityLogVisible.toggle() }
        } label: {
            HStack(spacing: Space.sm) {
                SwitchGlyph(on: session.agentPolicy != .paused, tint: Tok.Agent.base.color)
                Text("Agent").font(Tok.Face.ui(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.primary.color)
                if session.agentActionsLastMinute > 0 {
                    Text("\(session.agentActionsLastMinute)")
                        .font(Tok.Face.ui(Tok.Typography.Size.xs))
                        .foregroundStyle(Tok.Agent.deep.color)
                        .padding(.horizontal, Tok.Metric.gapTight)
                        .frame(height: Tok.Metric.switchHeight)
                        .background(Tok.Agent.tint.color, in: Capsule())
                }
            }
            .padding(.horizontal, Space.sm)
            .frame(height: Tok.Size.control)
            .contentShape(Rectangle())
        }
        .menuStyle(.button)
        .buttonStyle(.plain)
        .menuIndicator(.hidden)
        .help("Agent policy: \(session.agentPolicy.title)")
    }
}

/// Two flat glyphs; the active layout in ink, the other in secondary. No segmented chrome.
struct LayoutPicker: View {
    @Environment(Session.self) private var session

    var body: some View {
        HStack(spacing: Space.xs) {
            ForEach(InspectorLayout.allCases, id: \.self) { layout in
                layoutButton(layout, symbol: layout.symbol, help: layoutHelp(layout))
            }
            Button { session.splitView.toggle() } label: {
                Image(systemName: "square.split.2x1")
                    .font(.system(size: 15, weight: .regular))
                    .foregroundStyle(session.splitView ? Tok.Ink.primary.color : Tok.Ink.tertiary.color)
                    .frame(width: Tok.Size.control, height: Tok.Size.control)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help(session.splitView ? "Show one list (⌥⌘4)" : "Show two lists side by side (⌥⌘4)")
            .accessibilityAddTraits(session.splitView ? .isSelected : [])
        }
    }

    /// Verb + shortcut, not the menu title (C3).
    private func layoutHelp(_ layout: InspectorLayout) -> String {
        switch layout {
        case .horizontal: "Show the inspector below the list (⌥⌘1)"
        case .vertical: "Show the inspector beside the list (⌥⌘2)"
        case .detached: "Detach the inspector into its own window (⌥⌘3)"
        }
    }

    private func layoutButton(_ layout: InspectorLayout, symbol: String, help: String) -> some View {
        let on = session.layout == layout
        return Button { session.layout = layout } label: {
            Image(systemName: symbol)
                .font(.system(size: 15, weight: .regular))
                .foregroundStyle(on ? Tok.Ink.primary.color : Tok.Ink.tertiary.color)
                .frame(width: Tok.Size.control, height: Tok.Size.control)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(help)
        .accessibilityAddTraits(on ? .isSelected : [])
    }
}
