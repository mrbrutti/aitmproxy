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
            .help("Toggle sidebar")
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

/// `● aitmproxy · listening 127.0.0.1:8080 · HTTP/2`; the dot is green when
/// listening, grey when paused, amber while intercept is armed.
struct ListeningPill: View {
    @Environment(Session.self) private var session

    /// The embedded core's health bucket, or `nil` for an external core (then the
    /// pill follows capture/intercept as before, since the app does not own it).
    private var coreHealth: CoreHealth? { session.coreHealth.health }

    private var dot: DynamicColor {
        switch coreHealth {
        case .failed: return Tok.Status.serverError
        case .restarting: return Tok.Intercept.base
        default:
            if !session.capturing { return Tok.Ink.tertiary }
            return session.interceptArmed ? Tok.Intercept.base : Tok.Status.success
        }
    }

    var body: some View {
        HStack(spacing: Space.sm) {
            Circle().fill(dot.color).frame(width: Tok.Size.statusDot, height: Tok.Size.statusDot)
            HStack(spacing: 0) {
                Text("aitmproxy").fontWeight(.medium).foregroundStyle(Tok.Ink.primary.color)
                // The pill must tell the truth about the core: a failed embedded core
                // is not listening, so it must not keep reading "listening …".
                switch coreHealth {
                case .failed:
                    Text(" · core failed — not listening")
                case .restarting:
                    Text(" · restarting…")
                default:
                    Text(" · \(session.capturing ? "listening" : "paused") ")
                    Text(session.coreHealth.connection?.proxyAddress ?? session.listenAddress)
                        .font(Tok.Face.data(Tok.Typography.Size.sm, .medium))
                        .foregroundStyle(Tok.Ink.primary.color)
                    Text(" · HTTP/2")
                    if session.interceptArmed { Text(" · intercept armed") }
                }
            }
            .font(Tok.Face.ui(Tok.Typography.Size.sm))
            .foregroundStyle(Tok.Ink.secondary.color)
            .lineLimit(1)
        }
        .padding(.leading, Tok.Metric.padInner)
        .padding(.trailing, Space.md)
        .frame(height: Tok.Size.control)
        .background(Tok.Ground.raised.color, in: Capsule())
        .accessibilityElement(children: .combine)
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
                layoutButton(layout, symbol: layout.symbol, help: layout.title)
            }
            Button { session.splitView.toggle() } label: {
                Image(systemName: "square.split.2x1")
                    .font(.system(size: 15, weight: .regular))
                    .foregroundStyle(session.splitView ? Tok.Ink.primary.color : Tok.Ink.tertiary.color)
                    .frame(width: Tok.Size.control, height: Tok.Size.control)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help(session.splitView ? "Single list" : "Split view (⌥⌘4)")
            .accessibilityAddTraits(session.splitView ? .isSelected : [])
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
