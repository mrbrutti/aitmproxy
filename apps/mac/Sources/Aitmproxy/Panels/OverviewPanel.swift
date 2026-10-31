import AitmproxyKit
import AppKit
import SwiftUI

/// The Overview page (S-063): a tracked `OVERVIEW` label, a hairline grid of
/// stat tiles, then three bar lists — status classes, top hosts, timing
/// percentiles — side by side when the page is wide, stacked when it is not.
/// Bars are tertiary ink; hue appears only on the status-code labels.
struct OverviewPanel: View {
    @Environment(Session.self) private var session
    @State private var width: CGFloat = 0

    /// Below this the three sections stack.
    private static let sideBySideMin: CGFloat = 900

    private var stats: OverviewStats { OverviewStats(rows: session.rows) }

    var body: some View {
        let stats = stats
        ScrollView {
            VStack(alignment: .leading, spacing: Space.xl) {
                TrackedLabel("Overview").accessibilityAddTraits(.isHeader)
                StatTiles(stats: stats) { showStatus(.serverError) }
                sections(stats)
            }
            .padding(Space.margin)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
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
                               barColor: Palette.accent)
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

    /// Narrows the Connection Log to one status class (a status row or the Errors
    /// tile). The `none` bucket is "no status yet" — the negation of `~s`. There is
    /// no flow-state filter field, so the Paused tile has nothing to jump to.
    private func showStatus(_ statusClass: StatusClass?) {
        session.show(.connections)
        let row = statusClass
            .map { FilterRow(.status, .equals, String($0.rangeLabel.prefix(1))) }
            ?? FilterRow(.status, .contains, "", negated: true)
        session.filterAdvanced = false
        session.filterStack = FilterStack(rows: [row])
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
    /// Jump from the Errors tile to the 5xx filter — the only tile with a filter to
    /// jump to (Paused has no flow-state filter field to narrow on).
    var onErrors: () -> Void

    private struct Tile {
        var title: String
        var value: String
        var action: (() -> Void)? = nil
    }

    private var tiles: [Tile] {
        [
            Tile(title: "Flows", value: String(stats.flows)),
            Tile(title: "Hosts", value: String(stats.hosts)),
            Tile(title: "Clients", value: String(stats.clients)),
            Tile(title: "Paused", value: String(stats.paused)),
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
private struct BarSection<Rows: View>: View {
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
private struct BarRow: View {
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
