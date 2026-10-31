import AitmproxyKit
import SwiftUI

/// Left: Clear · Filter · Auto-select. Centre: counts. Right: memory,
/// throughput, the bus connection (foundation §2.7 "Status bar").
struct StatusBar: View {
    @Environment(Session.self) private var session

    var body: some View {
        HStack(spacing: Space.sm) {
            SmallButton("Clear") { session.clearSession(confirm: ClearConfirmation.ask) }
                .help("Clear every flow from the session (⌘⌫)")
            SmallButton("Filter", on: session.filterBarVisible) { session.filterBarVisible.toggle() }
                .help("Show or hide the filter bar (⌘F)")
            SmallButton("Auto-select", on: session.autoSelect) { session.autoSelect.toggle() }
                .help("Follow the newest flow as it arrives (⇧⌘A)")
            Spacer()
            HStack(spacing: Tok.Metric.gapMeta) {
                if let notice = session.clearNotice {
                    HStack(spacing: Tok.Metric.gapTight) {
                        Text("\(notice.text) —")
                        SmallButton("Undo") { session.undoClear() }
                            .help("Put the cleared flows back (⌘Z)")
                    }
                    .accessibilityIdentifier("clear-notice")
                }
                if let error = session.lastError {
                    Label(error, systemImage: "exclamationmark.triangle")
                        .labelStyle(.titleAndIcon)
                        .foregroundStyle(Tok.Status.serverError.color)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .help(error)
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
                // The three connection lanes, worded by the same table as the Status page; each
                // opens it. A role mismatch is the bus lane's warning, not a fourth item.
                ForEach(session.connectionSummary.lanes, id: \.kind) { lane in
                    Button { session.show(.status) } label: {
                        LaneDot(lane: lane)
                            .foregroundStyle(lane.state == .ok || lane.state == .off ? Tok.Ink.secondary.color : lane.state.color.color)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .help([lane.kind.title.capitalized + ": " + lane.word, lane.detail, lane.remedy].compactMap { $0 }.joined(separator: "\n"))
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
        .dimsWhenInactive()
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
