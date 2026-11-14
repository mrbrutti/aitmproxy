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
                    if summary.coreAddressShown {
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
/// are not recorded). Its position is the core's published `capturing` (`Session.capturing`,
/// refreshed from `proxy.status` every poll and from each pause/resume reply, so a pause by
/// another client — agent, TUI, web — shows here within one poll). The same entry as View ▸
/// Pause Proxy / Resume Proxy (⇧⌘R) and the palette. Live while the bus is connected as
/// operator — pause is a bus call, whichever core answers.
struct ProxySwitch: View {
    @Environment(Session.self) private var session
    var summary: ConnectionSummary

    var body: some View {
        ToolbarSwitch(
            title: "Proxy", on: session.capturing, tint: Tok.Status.success.color,
            enabled: ToolbarSwitches.proxyLive(summary, role: session.resolvedRole),
            help: ToolbarSwitches.proxyHelp(summary, role: session.resolvedRole, capturing: session.capturing)
        ) { on in ToolbarSwitches.flipProxy(session, on: on) }
    }
}

/// The capture extension's switch. Its position is the published fact, not the preference
/// (spec §1): on whenever the capture lane is doing anything — capturing, waiting for approval,
/// degraded — off when the lane is off; `captureChoice` carries it through a switch in flight.
/// Its colour is the lane's state, so "on, nothing in scope" shows the warning hue and
/// "waiting for approval" the working hue. Flips through `CaptureSwitch.set` — the same steps as Settings ▸
/// All Apps, Proxy ▸ Capture All Apps / Stop Capturing All Apps (⌃⌘A) and the Status card. Operator-only:
/// reached by a click here and nowhere else (`tools/check-capture-operator-only.sh` lists this
/// file beside those three).
struct CaptureExtensionSwitch: View {
    @Environment(Session.self) private var session
    var summary: ConnectionSummary

    var body: some View {
        let health = session.coreHealth
        let embedded = session.embeddedCoreActive
        let on = ToolbarSwitches.capturePosition(choice: health.captureChoice, lane: summary.capture)
        ToolbarSwitch(
            title: "All Apps", on: on, tint: summary.capture.state.color.color,
            enabled: ToolbarSwitches.captureLive(health, embedded: embedded),
            help: ToolbarSwitches.captureHelp(summary.capture, controlsAvailable: health.captureControlsAvailable,
                                              embedded: embedded, busy: health.captureBusy, choice: on)
        ) { on in ToolbarSwitches.flipCapture(session, on: on) }
    }
}

/// The switches' rules, help text and the two flips as plain functions, so the self-test can
/// drive them (ST-AC9) without a view and the views stay one line each.
@MainActor
enum ToolbarSwitches {
    /// Pause/resume is a bus call: live while the bus is connected AND the resolved role is the
    /// operator. The role is checked itself, not the lane's role-mismatch warning (that warning
    /// only fires against an Expected-role setting), so an agent-token connection with no
    /// expectation set still stands down and a pause from this switch is never logged as an
    /// agent action.
    static func proxyLive(_ summary: ConnectionSummary, role: String?) -> Bool {
        summary.bus.state == .ok && role == "operator"
    }

    /// The Proxy switch's flip: the same entry as View ▸ Pause Proxy / Resume Proxy.
    static func flipProxy(_ session: Session, on: Bool) {
        session.setCapturing(on)
    }

    /// The Capture switch's flip: the same steps as Settings ▸ Capture and Proxy ▸ Turn On/Off
    /// Capture. Operator-only (`tools/check-capture-operator-only.sh`).
    static func flipCapture(_ session: Session, on: Bool) {
        Task { await CaptureSwitch.set(on, session: session) }
    }

    static func proxyHelp(_ summary: ConnectionSummary, role: String?, capturing: Bool) -> String {
        guard proxyLive(summary, role: role) else { return "Bus \(summary.bus.word) — connect as operator to pause or resume the proxy" }
        return capturing
            ? "Pause the proxy: traffic still passes and new flows are not recorded (⇧⌘R)"
            : "Resume recording flows (⇧⌘R)"
    }

    /// The switch's resting position: the extension is on unless its lane is off.
    static func captureOn(_ lane: ConnectionLane) -> Bool { lane.state != .off }

    /// What the switch shows: the choice while a switch is in flight, else the lane's fact.
    static func capturePosition(choice: Bool?, lane: ConnectionLane) -> Bool { choice ?? captureOn(lane) }

    /// The same gate as Settings ▸ All Apps' toggle and Proxy ▸ Capture All Apps.
    static func captureLive(_ health: CoreHealthState, embedded: Bool) -> Bool {
        health.captureControlsAvailable && !health.captureBusy && embedded
    }

    static func captureHelp(_ lane: ConnectionLane, controlsAvailable: Bool, embedded: Bool, busy: Bool,
                            choice: Bool) -> String {
        if busy { return "Switching All Apps…" }
        if !controlsAvailable { return "All Apps capture is not in this build" }
        if !embedded { return "The active core is external — switch to the embedded core in Settings ▸ Bus to control capture" }
        var lines = [choice
            ? "Stop capturing all apps (⌃⌘A)"
            : "Capture all apps: every Mac app's traffic, including apps that ignore proxy settings, through the macOS extension (⌃⌘A)"]
        lines.append("\(lane.compact) — \(lane.detail)")
        if let remedy = lane.remedy { lines.append(remedy) }
        return lines.joined(separator: "\n")
    }
}

/// A word and a small switch: the toolbar's control for one on/off thing. A real `Toggle` under
/// a custom style, so VoiceOver gets a checkbox titled "Proxy" / "All Apps" with an on/off value
/// and AXPress flips it (a plain `Button` here exposed an untitled "toggle button" and swallowed
/// System Events clicks — found live, 2026-10-31). The track takes its owner's colour when on
/// (a lane's state colour, the agent teal) and tertiary when off; disabled drops the word to
/// tertiary and says why in `help`.
struct ToolbarSwitch: View {
    var title: String
    var on: Bool
    var tint: Color
    var enabled: Bool
    var help: String
    /// Receives the value the switch was flipped to.
    var action: (Bool) -> Void

    var body: some View {
        Toggle(title, isOn: Binding(get: { on }, set: { action($0) }))
            .toggleStyle(ToolbarSwitchStyle(title: title, tint: tint))
            .disabled(!enabled)
            .help(help)
    }
}

/// Draws a `Toggle` as `[●━] Word`: the shared `SwitchGlyph` and the title in ink (tertiary when
/// disabled). Tapping anywhere on it flips the binding.
struct ToolbarSwitchStyle: ToggleStyle {
    var title: String
    var tint: Color
    /// `.disabled` on the Toggle (or any parent) greys the track and the word together.
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        Button { configuration.isOn.toggle() } label: {
            HStack(spacing: Space.sm) {
                SwitchGlyph(on: configuration.isOn, tint: isEnabled ? tint : Tok.Ink.tertiary.color)
                configuration.label
                    .font(Tok.Face.ui(Tok.Typography.Size.sm))
                    .foregroundStyle(isEnabled ? Tok.Ink.primary.color : Tok.Ink.tertiary.color)
            }
            .padding(.horizontal, Space.sm)
            .frame(height: Tok.Size.control)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        // The Button is the element assistive tech reaches; the title drawn inside it is a
        // child, so name and value go here — VoiceOver reads "Proxy, on", not "toggle button".
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(title)
        .accessibilityValue(configuration.isOn ? "on" : "off")
        .accessibilityAddTraits(.isToggle)
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
                // A white knob in both appearances, as the system switch draws it: the track
                // under it is a status colour or the tertiary grey, never the accent.
                Circle().fill(.white)
                    .frame(width: Tok.Metric.switchKnob, height: Tok.Metric.switchKnob)
                    .padding(Tok.Metric.switchKnobInset)
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
