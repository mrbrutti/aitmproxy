import AitmproxyKit
import SwiftUI

/// The window toolbar (foundation §2.7 "Toolbar"): record/pause, compose,
/// clear · the listening pill · the Agent toggle, palette, layout.
struct ShellToolbar: ToolbarContent {
    @Environment(Session.self) private var session
    @Binding var sidebarVisible: Bool

    var body: some ToolbarContent {
        ToolbarItemGroup(placement: .navigation) {
            Button { sidebarVisible.toggle() } label: {
                Label("Toggle Sidebar", systemImage: Tok.Glyph.sidebar)
            }
            .help(sidebarVisible ? "Hide the sidebar (⌃⌘S)" : "Show the sidebar (⌃⌘S)")
            Button { session.setCapturing(!session.capturing) } label: {
                Label(session.capturing ? "Pause Capture" : "Resume Capture",
                      systemImage: session.capturing ? Tok.Glyph.pause : Tok.Glyph.record)
            }
            .help(session.capturing ? "Pause capture (⇧⌘R)" : "Resume capture (⇧⌘R)")
            Button { session.openCompose() } label: { Label("Compose", systemImage: Tok.Glyph.compose) }
                .help("Compose a request (⌘N)")
            Button { session.clearSession(confirm: ClearConfirmation.ask) } label: { Label("Clear Session", systemImage: Tok.Glyph.clear) }
                .help("Clear every flow from the session (⌘⌫)")
        }
        .sharedBackgroundVisibility(.hidden)
        ToolbarItem(placement: .principal) {
            ListeningPill()
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

/// `● aitmproxy · 127.0.0.1:8080 · ● bus · ◐ on, nothing in scope`: the three connection
/// lanes in the words the Status page uses, calm (dot only) while a lane is fine, worded
/// when it needs attention. Clicking opens the Status page. The core lane carries the
/// bound proxy address; "paused" and "intercept armed" stay as the capture-state words.
struct ListeningPill: View {
    @Environment(Session.self) private var session

    var body: some View {
        let summary = session.connectionSummary
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
            .background(Tok.Ground.raised.color, in: Capsule())
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .help(summary.lanes.map { "\($0.kind.title): \($0.word) — \($0.detail)" }.joined(separator: "\n") + "\nOpens Status (⌘0)")
        .accessibilityElement(children: .combine)
        .accessibilityLabel("aitmproxy: core \(summary.core.word), bus \(summary.bus.word), capture \(summary.capture.word)")
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
                Capsule()
                    .fill(session.agentPolicy == .paused ? Tok.Ink.tertiary.color : Tok.Agent.base.color)
                    .frame(width: Tok.Metric.switchWidth, height: Tok.Metric.switchHeight)
                    .overlay(alignment: session.agentPolicy == .paused ? .leading : .trailing) {
                        Circle().fill(.white).frame(width: Tok.Metric.switchKnob, height: Tok.Metric.switchKnob).padding(2)
                    }
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
