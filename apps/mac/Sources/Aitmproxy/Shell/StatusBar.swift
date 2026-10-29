import AitmproxyKit
import SwiftUI

/// Left: Clear · Filter · Auto-select. Centre: counts. Right: memory,
/// throughput, the bus connection (foundation §2.7 "Status bar").
struct StatusBar: View {
    @Environment(Session.self) private var session

    var body: some View {
        HStack(spacing: Space.sm) {
            SmallButton("Clear") {}
            SmallButton("Filter") {}
            SmallButton("Auto-select", on: session.autoSelect) { session.autoSelect.toggle() }
                .help("Follow the newest flow as it arrives (⇧⌘A)")
            Spacer()
            HStack(spacing: Tok.Metric.gapMeta) {
                if let error = session.lastError {
                    Text(error).foregroundStyle(Tok.Status.serverError.color).lineLimit(1)
                }
                if let summary = session.selectionSummary {
                    Text(summary.text).font(Tok.Face.data(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.primary.color)
                } else {
                    Text("\(session.selection.count) / \(session.visibleRows.count) rows")
                }
                if !session.paused.isEmpty {
                    Text("\(session.paused.count) paused").foregroundStyle(Tok.Intercept.deep.color)
                }
                if !session.scopeHosts.isEmpty { Text("\(session.scopeHosts.count) hosts in scope") }
                if session.findingsCount > 0 { Text("\(session.findingsCount) findings") }
            }
            Spacer()
            HStack(spacing: Tok.Metric.gapMeta) {
                if session.memoryBytes > 0 { Text(Format.bytes(session.memoryBytes)) }
                Text("↑ \(Format.rate(session.upBytesPerSecond))")
                Text("↓ \(Format.rate(session.downBytesPerSecond))")
                // The embedded core's health (Task 8): present only when the app
                // manages its own core; an external connection shows the bus dot alone.
                if let connection = session.coreHealth.connection {
                    CoreHealthDot(connection: connection) { session.coreLogVisible.toggle() }
                }
                HStack(spacing: Tok.Metric.gapTight) {
                    Circle().fill(busColor.color).frame(width: Tok.Size.statusDot, height: Tok.Size.statusDot)
                    Text(busText)
                }
                if let role = session.resolvedRole {
                    Label(role, systemImage: roleSymbol(role))
                        .labelStyle(.titleAndIcon)
                        .foregroundStyle(session.roleWarning ? Tok.Status.serverError.color : Tok.Ink.secondary.color)
                        .help(session.roleWarning
                            ? "Connected as \(role), not the role you expected (Settings ▸ Bus)"
                            : "Connected as \(role)")
                }
            }
            .font(Tok.Face.data(Tok.Typography.Size.sm))
        }
        .font(Tok.Face.ui(Tok.Typography.Size.sm))
        .foregroundStyle(Tok.Ink.secondary.color)
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.statusBar)
        .frame(maxWidth: .infinity)
        .background(Tok.Ground.raised.color)
        .overlay(alignment: .top) { Rule() }
    }

    private var busColor: DynamicColor {
        switch session.bus {
        case .connected: Tok.Status.success
        case .connecting: Tok.Intercept.base
        case .disconnected: Tok.Ink.tertiary
        case .failed: Tok.Status.serverError
        }
    }

    /// A key badge for operator, a plain person for agent, a warning triangle on mismatch.
    private func roleSymbol(_ role: String) -> String {
        if session.roleWarning { return "exclamationmark.triangle.fill" }
        return role == "operator" ? "person.badge.key.fill" : "person.fill"
    }

    private var busText: String {
        switch session.bus {
        case .connected(let addr): "bus \(addr)"
        case .connecting(let addr): "connecting \(addr)"
        case .disconnected: "bus offline"
        case .failed(let why): "bus: \(why)"
        }
    }
}

/// The status bar's 20px outlined buttons.
struct SmallButton: View {
    var title: String
    var on = false
    var action: () -> Void

    init(_ title: String, on: Bool = false, action: @escaping () -> Void) {
        self.title = title
        self.on = on
        self.action = action
    }

    var body: some View {
        Button(action: action) {
            Text(title)
                .font(Tok.Face.ui(Tok.Typography.Size.xs))
                .foregroundStyle(on ? Tok.Ink.primary.color : Tok.Ink.secondary.color)
                .padding(.horizontal, Space.sm)
                .frame(height: Tok.Metric.smallButton)
                .background(on ? Tok.Ground.active.color : Tok.Ground.surface.color, in: RoundedRectangle(cornerRadius: Tok.Radius.control))
                .overlay(RoundedRectangle(cornerRadius: Tok.Radius.control).strokeBorder(Tok.Line.control.color))
        }
        .buttonStyle(PressStyle())
    }
}
