import AitmproxyKit
import SwiftUI

/// The Overview page's second row (wave 2): Methods, Clients and L4 sessions,
/// side by side when the page is wide, stacked when it is not. Hue appears only
/// on the method labels and bars (the method badge pairs); everything else is ink.
struct OverviewBreakdownRow: View {
    @Environment(Session.self) private var session
    var breakdowns: OverviewBreakdowns
    var sideBySide: Bool
    /// A method row narrows the flow list to that method.
    var onMethod: (HTTPMethod) -> Void

    private static let methodWidth: CGFloat = 64
    private static let clientWidth: CGFloat = 120

    var body: some View {
        let layout = sideBySide
            ? AnyLayout(HStackLayout(alignment: .top, spacing: Space.xl))
            : AnyLayout(VStackLayout(alignment: .leading, spacing: Space.xl))
        layout {
            BarSection(title: "Methods", empty: breakdowns.methods.isEmpty ? "No flows yet" : nil) {
                ForEach(breakdowns.methods, id: \.method) { entry in
                    BarRow(label: entry.method.label, labelColor: entry.method.badge.fg,
                           labelWidth: Self.methodWidth, value: String(entry.count),
                           fraction: fraction(entry.count, of: breakdowns.methodMax),
                           barColor: entry.method.badge.fg.color,
                           action: { onMethod(entry.method) })
                        .accessibilityLabel("\(entry.method.label), \(entry.count)")
                }
            }
            BarSection(title: "Clients", empty: breakdowns.clients.isEmpty ? "No app attribution" : nil) {
                ForEach(breakdowns.clients, id: \.name) { entry in
                    BarRow(label: entry.name, labelColor: Tok.Ink.primary,
                           labelWidth: Self.clientWidth, value: String(entry.count),
                           fraction: fraction(entry.count, of: breakdowns.clientMax),
                           action: { session.show(.apps, group: .client(entry.name)) })
                        .help(entry.name)
                        .accessibilityLabel("\(entry.name), \(entry.count)")
                }
            }
            L4SessionsSection(sessions: breakdowns.l4Sessions, preview: breakdowns.l4Preview) { row in
                session.select(row.id)
                session.show(.domains)
            }
        }
    }

    private func fraction(_ n: Int, of total: Int) -> Double {
        total > 0 ? Double(n) / Double(total) : 0
    }
}

/// `L4 SESSIONS`: the count, then up to three sessions as `proto · target · n pkt`
/// rows that open the session, and "and n more" when the capture holds more.
private struct L4SessionsSection: View {
    var sessions: [FlowRow]
    var preview: [FlowRow]
    var open: (FlowRow) -> Void

    var body: some View {
        BarSection(title: "L4 sessions", empty: sessions.isEmpty ? "No L4 sessions" : nil) {
            HStack(alignment: .firstTextBaseline, spacing: Space.sm) {
                Text(String(sessions.count))
                    .font(Tok.Face.data(Tok.Typography.Size.lg, .medium))
                    .foregroundStyle(Tok.Ink.primary.color)
                Text(sessions.count == 1 ? "session" : "sessions")
                    .font(Tok.Face.ui(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.tertiary.color)
            }
            .accessibilityElement(children: .combine)
            ForEach(preview) { row in
                FlowListRow(row: row, title: OverviewBreakdowns.l4Summary(row),
                            titleColor: Tok.L4.base, trailing: row.l4?.sessionState.label ?? "",
                            trailingColor: Tok.Ink.secondary, help: OverviewBreakdowns.l4Summary(row),
                            hint: "Opens the session") { open(row) }
            }
            if sessions.count > preview.count {
                Text("and \(sessions.count - preview.count) more")
                    .font(Tok.Face.ui(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.tertiary.color)
            }
        }
    }
}

/// The Overview page's third row: Slowest flows, Recent errors and Largest
/// responses, three compact lists whose rows open the flow.
struct OverviewListsRow: View {
    @Environment(Session.self) private var session
    var breakdowns: OverviewBreakdowns
    var sideBySide: Bool

    var body: some View {
        let layout = sideBySide
            ? AnyLayout(HStackLayout(alignment: .top, spacing: Space.xl))
            : AnyLayout(VStackLayout(alignment: .leading, spacing: Space.xl))
        layout {
            BarSection(title: "Slowest flows", empty: breakdowns.slowest.isEmpty ? "None" : nil) {
                ForEach(breakdowns.slowest) { row in
                    FlowListRow(row: row, method: row.method, title: row.url,
                                trailing: Format.duration(row.duration), trailingColor: Tok.Ink.secondary) {
                        open(row)
                    }
                }
            }
            BarSection(title: "Recent errors", empty: breakdowns.recentErrors.isEmpty ? "None" : nil) {
                ForEach(breakdowns.recentErrors) { row in
                    FlowListRow(row: row, leading: row.startedAt.map { Format.clockTime($0) } ?? Format.dash,
                                method: row.method, title: row.url,
                                trailing: Self.statusText(row), trailingColor: Self.statusColor(row)) {
                        open(row)
                    }
                }
            }
            BarSection(title: "Largest responses", empty: breakdowns.largest.isEmpty ? "None" : nil) {
                ForEach(breakdowns.largest) { row in
                    FlowListRow(row: row, method: row.method, title: row.url,
                                trailing: Format.bytes(row.responseBytes), trailingColor: Tok.Ink.secondary) {
                        open(row)
                    }
                }
            }
        }
    }

    private func open(_ row: FlowRow) {
        session.select(row.id)
        session.show(.domains)
    }

    private static func statusText(_ row: FlowRow) -> String {
        if let status = row.status { return String(status) }
        return row.state.label
    }

    private static func statusColor(_ row: FlowRow) -> DynamicColor {
        if let status = row.status, let cls = StatusClass(status) { return cls.color }
        return row.state == .failed ? Tok.Status.serverError : Tok.Ink.secondary
    }
}

/// One compact list row: optional mono time, method in its badge colour, the URL
/// in primary ink (middle-truncated), a mono value on the right, and a chevron
/// that appears on hover. A `HoverRowStyle` button, like the host rows above.
private struct FlowListRow: View {
    var row: FlowRow
    var leading: String? = nil
    var method: HTTPMethod? = nil
    var title: String
    var titleColor: DynamicColor = Tok.Ink.primary
    var trailing: String
    var trailingColor: DynamicColor
    /// The hover help; the full URL unless the caller says otherwise (L4 rows have none).
    var help: String? = nil
    var hint = "Opens the flow"
    var action: () -> Void

    private static let leadingWidth: CGFloat = 64
    private static let methodWidth: CGFloat = 56
    private static let trailingWidth: CGFloat = 56

    var body: some View {
        Button(action: action) {
            HStack(spacing: Space.sm) {
                if let leading {
                    Text(leading)
                        .font(Tok.Face.data(Tok.Typography.Size.sm))
                        .foregroundStyle(Tok.Ink.secondary.color)
                        .frame(width: Self.leadingWidth, alignment: .leading)
                }
                if let method {
                    Text(method.label)
                        .font(Tok.Face.data(Tok.Typography.Size.sm, .medium))
                        .foregroundStyle(method.badge.fg.color)
                        .frame(width: Self.methodWidth, alignment: .leading)
                }
                Text(title)
                    .font(Tok.Face.data(Tok.Typography.Size.sm))
                    .foregroundStyle(titleColor.color)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Text(trailing)
                    .font(Tok.Face.data(Tok.Typography.Size.sm))
                    .foregroundStyle(trailingColor.color)
                    .lineLimit(1)
                    .frame(width: Self.trailingWidth, alignment: .trailing)
                HoverChevron()
            }
        }
        .buttonStyle(HoverRowStyle())
        .help(help ?? row.url)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(accessibilityText)
        .accessibilityHint(hint)
    }

    private var accessibilityText: String {
        [leading, method?.label, title, trailing].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: ", ")
    }
}
