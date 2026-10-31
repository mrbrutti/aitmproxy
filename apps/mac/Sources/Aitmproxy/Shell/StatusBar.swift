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
                // One connection item, from the same table as the Status page: the worst lane's
                // name and word while something needs attention, a single "connected" dot when all
                // is well. The sidebar's brand row and the Status page carry the rest; the bar
                // never repeats them (rule 64: small facts only, down here).
                let summary = session.connectionSummary
                let worst = summary.worst
                Button { session.show(.status) } label: {
                    HStack(spacing: Tok.Metric.gapTight) {
                        Circle().fill(worst.state.color.color).frame(width: Tok.Size.statusDot, height: Tok.Size.statusDot)
                        // "capture off" already names its lane; "failed" needs "core: failed".
                        Text(summary.overall == .ok ? "connected"
                             : worst.word.hasPrefix(worst.kind.title.lowercased()) ? worst.word
                             : "\(worst.kind.title.lowercased()): \(worst.word)")
                            .lineLimit(1)
                    }
                    .foregroundStyle(summary.overall == .ok ? Tok.Ink.secondary.color : worst.state.color.color)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .help(summary.lanes.map { "\($0.kind.title): \($0.word) — \($0.detail)" }.joined(separator: "\n") + "\nOpens Status (⌘0)")
                .accessibilityLabel("Connection: core \(summary.core.word), bus \(summary.bus.word), capture \(summary.capture.word)")
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
