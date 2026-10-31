import AitmproxyKit
import AppKit
import SwiftUI

/// The Overview page (S-063): a tracked `OVERVIEW` label, a hairline grid of
/// stat tiles, then three bar lists — status classes, top hosts, timing
/// percentiles — then Methods, Clients and L4 sessions, then three short lists
/// (slowest, recent errors, largest responses), each row side by side when the
/// page is wide, stacked when it is not. Bars are tertiary ink; hue appears only
/// on the status-code and method labels.
struct OverviewPanel: View {
    @Environment(Session.self) private var session
    @State private var width: CGFloat = 0

    /// Below this the three sections stack.
    private static let sideBySideMin: CGFloat = 900

    /// L4 sockets are not HTTP flows: the tiles, Status and Top hosts count HTTP and
    /// WebSocket rows only; `OverviewBreakdowns` carries the L4 sessions as their own number.
    private var stats: OverviewStats { OverviewStats(rows: OverviewBreakdowns.httpOnly(session.rows)) }
    private var breakdowns: OverviewBreakdowns { OverviewBreakdowns(rows: session.rows) }
    private var sideBySide: Bool { width >= Self.sideBySideMin }

    var body: some View {
        let stats = stats
        let breakdowns = breakdowns
        ScrollView {
            VStack(alignment: .leading, spacing: Space.xl) {
                TrackedLabel("Overview").accessibilityAddTraits(.isHeader)
                StatTiles(stats: stats, onFlows: { showAllFlows() }, onHosts: { session.show(.domains) },
                          onClients: { session.show(.apps) }, onPaused: { showPaused() }, onErrors: { showErrors() })
                sections(stats)
                    .gridProbe("overview.sections", area: "overview")
                OverviewBreakdownRow(breakdowns: breakdowns, sideBySide: sideBySide) { showMethod($0) }
                    .gridProbe("overview.breakdowns", area: "overview")
                OverviewListsRow(breakdowns: breakdowns, sideBySide: sideBySide)
                    .gridProbe("overview.lists", area: "overview")
            }
            .padding(Space.margin)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        // The page never reports a minimum width to the shell split: three-up rows would
        // otherwise nudge the sidebar divider by a fraction of a point and blur every edge.
        .frame(minWidth: 0, maxWidth: .infinity)
        .background(Tok.Ground.surface.color)
        .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { width = $0 }
        .gridArea("overview")
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Overview")
    }

    private func sections(_ stats: OverviewStats) -> some View {
        let layout = width < Self.sideBySideMin
            ? AnyLayout(VStackLayout(alignment: .leading, spacing: Space.xl))
            : AnyLayout(HStackLayout(alignment: .top, spacing: Space.xl))
        let hostWidth = Self.hostLabelWidth(stats.topHosts)
        return layout {
            BarSection(title: "Status", empty: stats.flows == 0 ? "No flows yet" : nil) {
                ForEach(Array(stats.statusClasses.enumerated()), id: \.offset) { _, entry in
                    BarRow(label: entry.statusClass?.rangeLabel ?? "none",
                           labelColor: entry.statusClass?.color ?? Tok.Ink.tertiary,
                           labelWidth: Self.codeWidth, value: String(entry.count),
                           fraction: Self.fraction(entry.count, of: stats.statusMax),
                           barColor: (entry.statusClass?.color ?? Tok.Ink.tertiary).color,
                           action: entry.count > 0 ? { showStatus(entry.statusClass) } : nil)
                        .accessibilityLabel("\(entry.statusClass?.rangeLabel ?? "none"), \(entry.count)")
                }
            }
            BarSection(title: "Top hosts", empty: stats.flows == 0 ? "No flows yet" : nil) {
                ForEach(stats.topHosts, id: \.host) { entry in
                    HostRow(entry: entry, labelWidth: hostWidth,
                            fraction: Self.fraction(entry.count, of: stats.hostMax)) {
                        session.show(.domains, group: .host(entry.host))
                    }
                }
            }
            BarSection(title: "Timing", empty: timingEmpty(stats)) {
                if let p = stats.percentiles {
                    let top = max(Self.seconds(p.p99), 0.001)
                    ForEach([("p50", p.p50), ("p90", p.p90), ("p99", p.p99)], id: \.0) { name, value in
                        BarRow(label: name, labelColor: Tok.Ink.secondary, labelWidth: Self.codeWidth,
                               value: Format.duration(value), fraction: Self.seconds(value) / top,
                               barColor: Tok.Ink.secondary.color)
                            .accessibilityLabel("\(name), \(Format.duration(value))")
                    }
                }
            }
        }
    }

    private func timingEmpty(_ stats: OverviewStats) -> String? {
        if stats.flows == 0 { return "No flows yet" }
        return stats.percentiles == nil ? "No completed flows yet" : nil
    }

    /// Narrows the Connection Log to one status class (a status row). The `none`
    /// bucket is "no status yet" — the negation of `~s`.
    private func showStatus(_ statusClass: StatusClass?) {
        let row = statusClass
            .map { FilterRow(.status, .equals, String($0.rangeLabel.prefix(1))) }
            ?? FilterRow(.status, .contains, "", negated: true)
        applyFilter(FilterStack(rows: [row]))
    }

    /// A Methods row: one method filter.
    private func showMethod(_ method: HTTPMethod) {
        applyFilter(FilterStack(rows: [FilterRow(.method, .equals, method.label)]))
    }

    /// The Flows tile: every flow, with any filter cleared.
    private func showAllFlows() {
        session.clearFilter()
        session.show(.domains)
    }

    /// The Paused tile: a single flow-state filter.
    private func showPaused() {
        applyFilter(FilterStack(rows: [FilterRow(.state, .equals, "paused")]))
    }

    /// The Errors tile: transport failures, killed flows, or 5xx — the exact set the
    /// Errors stat counts, as an OR of state and status terms.
    private func showErrors() {
        applyFilter(FilterStack(rows: [
            FilterRow(.state, .equals, "failed"),
            FilterRow(.state, .equals, "killed"),
            FilterRow(.status, .equals, "5"),
        ], combinator: .or))
    }

    /// Jumps to the Connection Log narrowed to `stack`, with the filter bar shown.
    private func applyFilter(_ stack: FilterStack) {
        session.show(.connections)
        session.filterAdvanced = false
        session.filterStack = stack
        session.filterBarVisible = true
    }

    private static let codeWidth: CGFloat = 40
    /// Top-hosts label: wide enough for the longest host, floored at 160 so bars
    /// stay aligned, capped at 260 so one long host does not crowd out the bar.
    private static let hostLabelMin: CGFloat = 160
    private static let hostLabelMax: CGFloat = 260

    private static func hostLabelWidth(_ hosts: [OverviewStats.HostCount]) -> CGFloat {
        let font = Tok.Face.nsData(Tok.Typography.Size.sm)
        let widest = hosts.reduce(CGFloat(0)) {
            max($0, ($1.host as NSString).size(withAttributes: [.font: font]).width)
        }
        return min(max(widest.rounded(.up), hostLabelMin), hostLabelMax)
    }

    private static func fraction(_ n: Int, of total: Int) -> Double {
        total > 0 ? Double(n) / Double(total) : 0
    }

    private static func seconds(_ d: Duration) -> Double {
        Double(d.components.seconds) + Double(d.components.attoseconds) / 1e18
    }
}

/// Flows · Hosts · Clients · Paused · Errors · ↑ Bytes · ↓ Bytes on one
/// hairline grid: no fills, no shadows; a tracked label over a mono number.
private struct StatTiles: View {
    var stats: OverviewStats
    /// Flows, Hosts and Clients open the matching list page; Paused and Errors jump
    /// to the matching flow filter.
    var onFlows: () -> Void
    var onHosts: () -> Void
    var onClients: () -> Void
    var onPaused: () -> Void
    var onErrors: () -> Void

    private struct Tile {
        var title: String
        var value: String
        var action: (() -> Void)? = nil
    }

    private var tiles: [Tile] {
        [
            Tile(title: "Flows", value: String(stats.flows), action: onFlows),
            Tile(title: "Hosts", value: String(stats.hosts), action: onHosts),
            Tile(title: "Clients", value: String(stats.clients), action: onClients),
            Tile(title: "Paused", value: String(stats.paused), action: onPaused),
            Tile(title: "Errors", value: String(stats.errors), action: onErrors),
            Tile(title: "↑ Bytes", value: Format.bytes(stats.requestBytes)),
            Tile(title: "↓ Bytes", value: Format.bytes(stats.responseBytes)),
        ]
    }

    var body: some View {
        HStack(spacing: 0) {
            ForEach(Array(tiles.enumerated()), id: \.offset) { index, tile in
                if index > 0 { VRule(color: Tok.Line.rule) }
                StatTile(title: tile.title, value: tile.value, action: tile.action)
            }
        }
        .fixedSize(horizontal: false, vertical: true)
        .overlay(alignment: .top) { Rule(color: Tok.Line.rule) }
        .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
        .gridProbe("overview.tiles", area: "overview")
    }
}

/// One stat tile: a tracked label over a mono number. An actionable tile (Errors)
/// gains a hover fill and jumps to the matching filter when clicked.
private struct StatTile: View {
    var title: String
    var value: String
    var action: (() -> Void)?
    @State private var hovered = false

    private var tile: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            TrackedLabel(title)
            Text(value)
                .font(Tok.Face.data(Tok.Typography.Size.xl, .medium))
                .foregroundStyle(Tok.Ink.primary.color)
                .lineLimit(1)
                .minimumScaleFactor(0.7)
        }
        .padding(Space.lg)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    var body: some View {
        Group {
            if let action {
                Button(action: action) {
                    tile.background(hovered ? Tok.Ground.hover.color : .clear)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .onHover { hovered = $0 }
                .accessibilityHint("Shows its flows")
            } else {
                tile
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(title.replacingOccurrences(of: "↑ ", with: "Request ")
            .replacingOccurrences(of: "↓ ", with: "Response "))
        .accessibilityValue(value)
    }
}

/// A tracked title over a short list of bars; the empty words in its place.
/// Shared with the lower rows in OverviewBreakdowns.swift.
struct BarSection<Rows: View>: View {
    var title: String
    var empty: String?
    @ViewBuilder var rows: Rows

    var body: some View {
        VStack(alignment: .leading, spacing: Space.lg) {
            TrackedLabel(title).accessibilityAddTraits(.isHeader)
            if let empty {
                Text(empty)
                    .font(Tok.Face.ui(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.tertiary.color)
            } else {
                VStack(alignment: .leading, spacing: Space.md) { rows }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .contain)
        .accessibilityLabel(title)
    }
}

/// Label left, bar in the middle, mono value right. With an `action` the row is a
/// button (hover fill) that narrows the flow list; without one it is inert (Timing).
struct BarRow: View {
    var label: String
    var labelColor: DynamicColor
    var labelWidth: CGFloat
    var value: String
    var fraction: Double
    var barColor: Color = Tok.Ink.secondary.color
    var action: (() -> Void)? = nil
    @State private var hovered = false

    static let valueWidth: CGFloat = 56

    private var content: some View {
        HStack(spacing: Space.md) {
            Text(label)
                .font(Tok.Face.data(Tok.Typography.Size.sm, .medium))
                .foregroundStyle(labelColor.color)
                .lineLimit(1)
                .truncationMode(.middle)
                .frame(width: labelWidth, alignment: .leading)
            Bar(fraction: fraction, color: barColor)
            Text(value)
                .font(Tok.Face.data(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.secondary.color)
                .frame(width: BarRow.valueWidth, alignment: .trailing)
        }
    }

    var body: some View {
        if let action {
            Button(action: action) {
                content
                    .padding(.horizontal, Space.xs)
                    .frame(height: Tok.Size.Row.dense)
                    .background(hovered ? Tok.Ground.hover.color : .clear,
                                in: RoundedRectangle(cornerRadius: Tok.Radius.badge))
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .onHover { hovered = $0 }
            .accessibilityElement(children: .ignore)
            .accessibilityHint("Shows its flows")
        } else {
            content.accessibilityElement(children: .ignore)
        }
    }
}

/// A host row is a button: it narrows the flow list to that host.
private struct HostRow: View {
    var entry: OverviewStats.HostCount
    var labelWidth: CGFloat
    var fraction: Double
    var action: () -> Void
    @State private var hovered = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: Space.md) {
                Text(entry.host)
                    .font(Tok.Face.data(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.primary.color)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .frame(width: labelWidth, alignment: .leading)
                    .help(entry.host)
                Bar(fraction: fraction)
                Text(String(entry.count))
                    .font(Tok.Face.data(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.secondary.color)
                    .frame(width: BarRow.valueWidth, alignment: .trailing)
            }
            .padding(.horizontal, Space.xs)
            .frame(height: Tok.Size.Row.dense)
            .background(hovered ? Tok.Ground.hover.color : .clear, in: RoundedRectangle(cornerRadius: Tok.Radius.badge))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovered = $0 }
        .accessibilityLabel("\(entry.host), \(entry.count)")
        .accessibilityHint("Shows its flows")
    }
}

/// The bar itself: tertiary ink, 8 pt tall, badge radius, no track.
private struct Bar: View {
    var fraction: Double
    var color: Color = Tok.Ink.secondary.color
    static let height: CGFloat = 8

    var body: some View {
        GeometryReader { proxy in
            RoundedRectangle(cornerRadius: Tok.Radius.badge)
                .fill(color)
                .frame(width: fraction > 0 ? max(Self.height / 2, proxy.size.width * min(fraction, 1)) : 0)
        }
        .frame(height: Self.height)
        .frame(maxWidth: .infinity)
        .accessibilityHidden(true)
    }
}
