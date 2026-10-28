import AitmproxyKit
import SwiftUI

/// The activity log (S-057): a right-side panel, header kept in view, rows
/// `time · origin · command · args · result` at 28 pt, agent rows with a
/// 2 pt teal edge, pending gated requests with Approve once / Deny.
struct ActivityLogPanel: View {
    @Bindable var state: ActivityState
    /// On the Agent page the log fills the width; as a side panel it is 360 wide behind a rule.
    var inline = false

    static let panelWidth: CGFloat = 360

    private static let originOptions: [(ActivityEntry.Origin?, String)] = [
        (nil, "All"), (.agent, "Agent"), (.operator, "Operator"), (.cli, "CLI"),
    ]

    var body: some View {
        VStack(spacing: 0) {
            header
            Rule()
            if let note = state.note {
                Hint(text: note).padding(.leading, Space.md).frame(maxWidth: .infinity, alignment: .leading)
                Rule(color: Tok.Line.rule)
            }
            let rows = state.visible
            if rows.isEmpty {
                Text("No activity yet.")
                    .font(Tok.Face.ui(Tok.Typography.Size.md))
                    .foregroundStyle(Tok.Ink.tertiary.color)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(rows) { entry in
                            ActivityRow(entry: entry, state: state)
                        }
                    }
                }
            }
        }
        .frame(width: inline ? nil : Self.panelWidth)
        .frame(maxWidth: inline ? .infinity : nil, maxHeight: .infinity)
        .background(Tok.Ground.surface.color)
        .overlay(alignment: .leading) { if !inline { VRule() } }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Activity log")
    }

    private var header: some View {
        HStack(spacing: Space.md) {
            TrackedLabel("Activity")
            Spacer(minLength: Space.sm)
            FlatSegment(options: Self.originOptions, selection: $state.filter)
        }
        .padding(.horizontal, Space.md)
        .frame(height: Tok.Size.filterBar)
    }
}

/// One invocation. Pending rows take 36 pt so the bar buttons sit inside them.
private struct ActivityRow: View {
    var entry: ActivityEntry
    var state: ActivityState

    private var isPending: Bool { entry.result == .pending }

    var body: some View {
        HStack(spacing: Space.md) {
            Text(Format.time(entry.at))
                .font(Tok.Face.data(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.secondary.color)
                .frame(width: 96, alignment: .leading)
            Text(entry.origin.title)
                .font(Tok.Face.ui(Tok.Typography.Size.sm, entry.origin == .agent ? .medium : .regular))
                .foregroundStyle(entry.origin == .agent ? Tok.Agent.deep.color : Tok.Ink.secondary.color)
                .frame(width: 56, alignment: .leading)
            Text(entry.command)
                .font(Tok.Face.data(Tok.Typography.Size.md))
                .foregroundStyle(Tok.Ink.primary.color)
                .lineLimit(1)
                .layoutPriority(1)
            if !entry.argsSummary.isEmpty {
                Text(entry.argsSummary)
                    .font(Tok.Face.data(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.tertiary.color)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .help(entry.argsSummary)
            }
            Spacer(minLength: Space.sm)
            if isPending {
                PrimaryButton("Approve once") { state.approve(entry) }
                FlatButton("Deny") { state.deny(entry) }
            } else {
                result
            }
        }
        .padding(.horizontal, Space.md)
        .frame(height: isPending ? Tok.Size.tabBar : Tok.Size.Row.dense)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(isPending ? Tok.Agent.tint.color.opacity(0.5) : .clear)
        .overlay(alignment: .leading) {
            if entry.origin == .agent { Rectangle().fill(Tok.Agent.base.color).frame(width: 2) }
        }
        .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(entry.origin.title) \(entry.command) \(entry.result.text)")
    }

    @ViewBuilder private var result: some View {
        switch entry.result {
        case .ok:
            Text("ok").font(Tok.Face.data(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.secondary.color)
        case .error(let message):
            Text("error").font(Tok.Face.data(Tok.Typography.Size.sm, .medium))
                .foregroundStyle(Tok.Status.serverError.color)
                .help(message)
        case .pending:
            Text("pending").font(Tok.Face.data(Tok.Typography.Size.sm)).foregroundStyle(Tok.Ink.tertiary.color)
        }
    }
}

/// The editorial section label: 11/500 tracked capitals in the tertiary tier
/// (the sidebar group label, the sheets' "HISTORY" and "BREAKPOINT RULES").
struct TrackedLabel: View {
    var text: String

    init(_ text: String) { self.text = text }

    var body: some View {
        Text(text.uppercased())
            .font(Tok.Face.ui(Tok.Typography.Size.xs, .medium))
            .tracking(0.6)
            .foregroundStyle(Tok.Ink.tertiary.color)
            .lineLimit(1)
    }
}
