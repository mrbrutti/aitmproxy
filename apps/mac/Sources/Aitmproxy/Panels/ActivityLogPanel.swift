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
                .gridProbe("activity-head", area: "activity", edge: nil)
            Rule()
            if let note = state.note {
                Hint(text: note).padding(.leading, Space.md).frame(maxWidth: .infinity, alignment: .leading)
                Rule(color: Tok.Line.rule)
            }
            let rows = state.visible
            if rows.isEmpty {
                ContentUnavailableView {
                    Label("No activity yet", systemImage: "list.bullet.rectangle")
                } description: {
                    Text("Agent, operator and CLI commands appear here as they run.")
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(rows) { entry in
                            ActivityRow(entry: entry, state: state, inline: inline)
                        }
                    }
                }
                .gridProbe("activity-rows", area: "activity", edge: nil)
            }
        }
        .frame(width: inline ? nil : Self.panelWidth)
        .frame(maxWidth: inline ? .infinity : nil, maxHeight: .infinity)
        .background(Tok.Ground.surface.color)
        .gridArea("activity", inset: 0)
        .overlay(alignment: .leading) { if !inline { VRule() } }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Activity log")
    }

    private var header: some View {
        PageHeader("Activity") {
            FlatSegment(options: Self.originOptions, selection: $state.filter)
        }
    }
}

/// One invocation. Pending rows take 36 pt so the bar buttons sit inside them.
/// In the 360 pt side panel (`!inline`) the time drops to `HH:mm:ss`, the args
/// summary is hidden, and the Approve / Deny controls hold their size and fall
/// back to icon buttons when the row is too tight (otherwise they crushed to a
/// black square and a lone "D").
private struct ActivityRow: View {
    var entry: ActivityEntry
    var state: ActivityState
    var inline = true

    private var isPending: Bool { entry.result == .pending }

    /// `HH:mm:ss` without milliseconds for the narrow panel — formatted here, not
    /// in the shared `Format`, which the whole app depends on.
    private var timeText: String {
        guard !inline else { return Format.time(entry.at) }
        return entry.at.formatted(.dateTime.hour(.twoDigits(amPM: .omitted)).minute(.twoDigits).second(.twoDigits))
    }

    var body: some View {
        HStack(spacing: Space.md) {
            Text(timeText)
                .font(Tok.Face.data(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.secondary.color)
                .fixedSize()
                .frame(width: inline ? 96 : 68, alignment: .leading)
            Text(entry.origin.title)
                .font(Tok.Face.ui(Tok.Typography.Size.sm, entry.origin == .agent ? .medium : .regular))
                .foregroundStyle(entry.origin == .agent ? Tok.Agent.deep.color : Tok.Ink.secondary.color)
                .fixedSize()
                .frame(width: 56, alignment: .leading)
            Text(entry.command)
                .font(Tok.Face.data(Tok.Typography.Size.md))
                .foregroundStyle(Tok.Ink.primary.color)
                .lineLimit(1)
                .truncationMode(.middle)
            if inline, !entry.argsSummary.isEmpty {
                Text(entry.argsSummary)
                    .font(Tok.Face.data(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.tertiary.color)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .help(entry.argsSummary)
            }
            Spacer(minLength: Space.sm)
            if isPending {
                actions
            } else {
                result.fixedSize().layoutPriority(1)
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

    /// Approve / Deny: full labels on the wide Agent page, compact icon buttons in
    /// the 360 pt side panel so the command keeps its room (and never crushes to a
    /// black square and a lone "D"). Fixed-size so they hold their width.
    @ViewBuilder private var actions: some View {
        Group {
            if inline {
                HStack(spacing: Space.sm) {
                    PrimaryButton("Approve once") { state.approve(entry) }
                    FlatButton("Deny") { state.deny(entry) }
                }
            } else {
                HStack(spacing: Space.xs) {
                    iconButton("checkmark", help: "Approve once — run this command one time") { state.approve(entry) }
                    iconButton("xmark", help: "Deny this request") { state.deny(entry) }
                }
            }
        }
        .fixedSize()
        .layoutPriority(1)
    }

    private func iconButton(_ symbol: String, help: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: symbol)
                .font(.system(size: Tok.Size.iconInline, weight: .medium))
                .foregroundStyle(Tok.Ink.secondary.color)
                .frame(width: Tok.Size.control, height: Tok.Size.control)
                .contentShape(Rectangle())
        }
        .buttonStyle(PressStyle())
        .help(help)
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
