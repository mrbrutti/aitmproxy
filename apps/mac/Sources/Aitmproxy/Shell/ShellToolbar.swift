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
            Button { session.capturing.toggle() } label: {
                Label(session.capturing ? "Pause Capture" : "Resume Capture",
                      systemImage: session.capturing ? Tok.Glyph.pause : Tok.Glyph.record)
            }
            .help(session.capturing ? "Pause capture" : "Resume capture")
            Button {} label: { Label("Compose", systemImage: Tok.Glyph.compose) }
                .help("Compose a request (n)")
            Button {} label: { Label("Clear", systemImage: Tok.Glyph.clear) }
                .help("Clear the session")
        }
        ToolbarItem(placement: .principal) {
            ListeningPill()
        }
        ToolbarItemGroup(placement: .primaryAction) {
            AgentToggle()
            Button {} label: { Label("Command Palette", systemImage: Tok.Glyph.palette) }
                .help("Command palette (⌘K)")
            LayoutPicker()
        }
    }
}

/// `● aitmproxy · listening 127.0.0.1:8080 · HTTP/2`; the dot is green when
/// listening, grey when paused, amber while intercept is armed.
struct ListeningPill: View {
    @Environment(Session.self) private var session

    private var dot: DynamicColor {
        if !session.capturing { return Tok.Ink.tertiary }
        return session.interceptArmed ? Tok.Intercept.base : Tok.Status.success
    }

    var body: some View {
        HStack(spacing: Space.sm) {
            Circle().fill(dot.color).frame(width: Tok.Size.statusDot, height: Tok.Size.statusDot)
            HStack(spacing: 0) {
                Text("aitmproxy").fontWeight(.medium).foregroundStyle(Tok.Ink.primary.color)
                Text(" · \(session.capturing ? "listening" : "paused") ")
                Text(session.listenAddress).font(Tok.Face.data(Tok.Typography.Size.sm, .medium))
                    .foregroundStyle(Tok.Ink.primary.color)
                Text(" · HTTP/2")
                if session.interceptArmed { Text(" · intercept armed") }
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
            Picker("Agent policy", selection: $session.agentPolicy) {
                ForEach(AgentPolicy.allCases, id: \.self) { Text($0.title).tag($0) }
            }
            .pickerStyle(.inline)
            Divider()
            Button("Activity Log…") {}
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
            .padding(.horizontal, Tok.Metric.padInner)
            .frame(height: Tok.Size.control)
            .overlay(RoundedRectangle(cornerRadius: Tok.Radius.control).strokeBorder(Tok.Line.control.color))
        }
        .menuStyle(.button)
        .buttonStyle(.plain)
        .help("Agent policy: \(session.agentPolicy.title)")
    }
}

struct LayoutPicker: View {
    @Environment(Session.self) private var session

    var body: some View {
        @Bindable var session = session
        Picker("Layout", selection: $session.layout) {
            Image(systemName: "rectangle.split.1x2").tag(InspectorLayout.horizontal)
                .help("Inspector below")
            Image(systemName: Tok.Glyph.split).tag(InspectorLayout.vertical)
                .help("Inspector right")
        }
        .pickerStyle(.segmented)
        .labelsHidden()
    }
}
