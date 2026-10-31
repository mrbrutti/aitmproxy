import AitmproxyKit
import Charts
import SwiftUI

/// The Connection page's dashboard band (S-064 redesign): a dense, graph-first
/// header that sits over the flow table. The hero is a status-segmented
/// "Traffic over time" histogram (interactive on hover); beside it compact
/// Status and Latency cards. It replaces the old derived connection table.
/// Hue comes only from the status tokens; the layout stays on the 4 pt grid.
struct ConnectionDashboard: View {
    @Environment(Session.self) private var session

    /// The side column with the Status and Latency cards.
    private static let sideWidth: CGFloat = 280

    var body: some View {
        // Follow the filtered view so the chip bar and filter bar drive the band,
        // not just the full capture.
        let rows = session.visibleRows
        let stats = OverviewStats(rows: rows)
        let series = TrafficSeries(rows: rows)
        HStack(alignment: .top, spacing: Space.md) {
            DashCard(title: "Traffic over time", trailing: series.total == 1 ? "1 flow" : "\(series.total) flows") {
                TrafficChart(series: series)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .gridProbe("connection.traffic", area: "connection-dashboard")
            VStack(spacing: Space.md) {
                DashCard(title: "Status") { StatusMix(stats: stats) }
                DashCard(title: "Latency") { LatencyMini(stats: stats) }
                Spacer(minLength: 0)
            }
            .frame(width: Self.sideWidth)
        }
        .padding(Space.lg)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Tok.Ground.page.color)
        .gridArea("connection-dashboard", inset: 0)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Connection dashboard")
    }
}

// MARK: - Card

/// A titled card on the page: a tracked label (and an optional trailing count)
/// over content, on `surface` with a hairline border. Cards are content, so no
/// shadow and no glass.
private struct DashCard<Content: View>: View {
    var title: String
    var trailing: String?
    @ViewBuilder var content: Content

    init(title: String, trailing: String? = nil, @ViewBuilder content: () -> Content) {
        self.title = title
        self.trailing = trailing
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            HStack(spacing: Space.sm) {
                TrackedLabel(title).accessibilityAddTraits(.isHeader)
                if let trailing {
                    Spacer(minLength: Space.xs)
                    Text(trailing)
                        .font(Tok.Face.data(Tok.Typography.Size.sm, .medium))
                        .foregroundStyle(Tok.Ink.secondary.color)
                }
            }
            content
        }
        .padding(Space.md)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Tok.Ground.surface.color, in: RoundedRectangle(cornerRadius: Tok.Radius.panel))
        .overlay(RoundedRectangle(cornerRadius: Tok.Radius.panel).strokeBorder(Tok.Line.border.color))
        .accessibilityElement(children: .contain)
        .accessibilityLabel(title)
    }
}

// MARK: - Traffic chart

/// One flow's status class, as a chartable category. `.other` holds pending,
/// paused and killed flows (no HTTP status).
enum TrafficClass: String, CaseIterable, Identifiable {
    case s2xx, s3xx, s4xx, s5xx, s1xx, other

    var id: String { rawValue }

    var label: String {
        switch self {
        case .s1xx: "1xx"
        case .s2xx: "2xx"
        case .s3xx: "3xx"
        case .s4xx: "4xx"
        case .s5xx: "5xx"
        case .other: "none"
        }
    }

    var token: DynamicColor {
        switch self {
        case .s1xx: Tok.Status.informational
        case .s2xx: Tok.Status.success
        case .s3xx: Tok.Status.redirect
        case .s4xx: Tok.Status.clientError
        case .s5xx: Tok.Status.serverError
        case .other: Tok.Status.killed
        }
    }

    var color: Color { token.color }

    init(statusClass: StatusClass?) {
        switch statusClass {
        case .informational: self = .s1xx
        case .success: self = .s2xx
        case .redirect: self = .s3xx
        case .clientError: self = .s4xx
        case .serverError: self = .s5xx
        case nil: self = .other
        }
    }

    init(status: Int?) {
        self.init(statusClass: status.flatMap(StatusClass.init))
    }
}

/// Application-layer flows binned into even time buckets, one mark per
/// (bucket, status class). L4 flows are left out — this is request traffic.
/// Buckets are categorical (padded indices) so bars render evenly and keep
/// their slot when empty; the count adapts to the sample.
struct TrafficSeries {
    struct Mark: Identifiable {
        let id: Int
        let bucket: String
        let klass: TrafficClass
        let count: Int
    }

    let marks: [Mark]
    /// Every bucket label in order, so empty buckets keep their slot.
    let bucketLabels: [String]
    /// A few bucket labels to annotate with their wall-clock time.
    let ticks: [(bucket: String, time: String)]
    let total: Int

    var isEmpty: Bool { total == 0 }

    init(rows: [FlowRow]) {
        let times = rows.filter { $0.l4 == nil }.compactMap(\.startedAt)
        guard let lo = times.min(), let hi = times.max() else {
            marks = []
            bucketLabels = []
            ticks = []
            total = 0
            return
        }
        // Aim for ~2 flows per bar, clamped so a small sample still reads as a
        // histogram and a large one stays legible.
        let n = max(8, min(32, times.count / 2))
        let span = max(hi.timeIntervalSince(lo), 1)
        let size = span / Double(n)
        func label(_ b: Int) -> String { String(format: "%02d", b) }
        var counts = Array(repeating: [TrafficClass: Int](), count: n)
        var sum = 0
        for row in rows where row.l4 == nil {
            guard let at = row.startedAt else { continue }
            let bucket = min(n - 1, max(0, Int(at.timeIntervalSince(lo) / size)))
            counts[bucket][TrafficClass(status: row.status), default: 0] += 1
            sum += 1
        }
        total = sum
        bucketLabels = (0..<n).map(label)

        var out: [Mark] = []
        for bucket in 0..<n {
            for (classIndex, klass) in TrafficClass.allCases.enumerated() {
                let count = counts[bucket][klass] ?? 0
                if count > 0 {
                    out.append(Mark(id: bucket * TrafficClass.allCases.count + classIndex,
                                    bucket: label(bucket), klass: klass, count: count))
                }
            }
        }
        marks = out
        // Whole seconds: millisecond ticks truncated at the plot edges.
        ticks = [0, n / 3, 2 * n / 3, n - 1].map {
            (label($0), Format.clockTime(lo.addingTimeInterval(size * Double($0))))
        }
    }
}

/// The hero: a status-stacked histogram of requests over time.
private struct TrafficChart: View {
    var series: TrafficSeries

    private static let order: [TrafficClass] = [.s2xx, .s3xx, .s4xx, .s5xx, .s1xx, .other]

    var body: some View {
        if series.isEmpty {
            ContentUnavailableView {
                Label("No traffic yet", systemImage: "chart.bar.xaxis")
            } description: {
                Text("Requests appear here as clients connect through the proxy.")
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            Chart(series.marks) { mark in
                BarMark(
                    x: .value("Time", mark.bucket),
                    y: .value("Requests", mark.count)
                )
                .foregroundStyle(by: .value("Status", mark.klass.label))
                .cornerRadius(1)
            }
            .chartForegroundStyleScale(domain: Self.order.map(\.label), range: Self.order.map(\.color))
            .chartLegend(.hidden)
            .chartXScale(domain: series.bucketLabels)
            .chartXAxis {
                AxisMarks(values: series.ticks.map(\.bucket)) { value in
                    AxisGridLine().foregroundStyle(Tok.Line.rule.color)
                    AxisValueLabel {
                        if let bucket = value.as(String.self),
                           let tick = series.ticks.first(where: { $0.bucket == bucket }) {
                            Text(tick.time)
                                .font(Tok.Face.data(Tok.Typography.Size.xs))
                                .foregroundStyle(Tok.Ink.tertiary.color)
                        }
                    }
                }
            }
            .chartYAxis {
                AxisMarks(position: .leading, values: .automatic(desiredCount: 3)) { value in
                    AxisGridLine().foregroundStyle(Tok.Line.rule.color)
                    AxisValueLabel {
                        if let count = value.as(Double.self) {
                            Text("\(Int(count))")
                                .font(Tok.Face.data(Tok.Typography.Size.xs))
                                .foregroundStyle(Tok.Ink.tertiary.color)
                        }
                    }
                }
            }
            .accessibilityLabel("Traffic over time, \(series.total) flows")
        }
    }
}

// MARK: - Status card

/// A slim stacked proportion bar over a two-column legend of class counts.
private struct StatusMix: View {
    var stats: OverviewStats

    private struct Segment: Identifiable {
        let klass: TrafficClass
        let count: Int
        var id: TrafficClass { klass }
    }

    private var segments: [Segment] {
        stats.statusClasses
            .map { Segment(klass: TrafficClass(statusClass: $0.statusClass), count: $0.count) }
            .filter { $0.count > 0 }
    }

    private var total: Int { segments.reduce(0) { $0 + $1.count } }

    var body: some View {
        if total == 0 {
            Text("No flows yet")
                .font(Tok.Face.ui(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.tertiary.color)
        } else {
            VStack(alignment: .leading, spacing: Space.md) {
                GeometryReader { geo in
                    HStack(spacing: 0) {
                        ForEach(segments) { seg in
                            Rectangle()
                                .fill(seg.klass.color)
                                .frame(width: max(0, geo.size.width * Double(seg.count) / Double(total)))
                        }
                    }
                }
                .frame(height: 8)
                .clipShape(RoundedRectangle(cornerRadius: Tok.Radius.badge))

                LazyVGrid(columns: [GridItem(.flexible(), alignment: .leading),
                                    GridItem(.flexible(), alignment: .leading)],
                          alignment: .leading, spacing: Space.sm) {
                    ForEach(segments) { seg in
                        HStack(spacing: Space.xs) {
                            RoundedRectangle(cornerRadius: Tok.Radius.badge)
                                .fill(seg.klass.color)
                                .frame(width: 8, height: 8)
                            Text(seg.klass.label)
                                .font(Tok.Face.data(Tok.Typography.Size.xs))
                                .foregroundStyle(Tok.Ink.secondary.color)
                            Text("\(seg.count)")
                                .font(Tok.Face.data(Tok.Typography.Size.xs, .medium))
                                .foregroundStyle(Tok.Ink.primary.color)
                        }
                        .accessibilityElement(children: .ignore)
                        .accessibilityLabel("\(seg.klass.label), \(seg.count)")
                    }
                }
            }
        }
    }
}

// MARK: - Latency card

/// p50 · p90 · p99 as mini bullet bars, scaled to p99.
private struct LatencyMini: View {
    var stats: OverviewStats

    var body: some View {
        if let p = stats.percentiles {
            let top = max(Self.seconds(p.p99), 0.001)
            VStack(alignment: .leading, spacing: Space.sm) {
                row("p50", p.p50, top)
                row("p90", p.p90, top)
                row("p99", p.p99, top)
            }
        } else {
            Text(stats.flows == 0 ? "No flows yet" : "No completed flows yet")
                .font(Tok.Face.ui(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.tertiary.color)
        }
    }

    private func row(_ label: String, _ value: Duration, _ top: Double) -> some View {
        HStack(spacing: Space.sm) {
            Text(label)
                .font(Tok.Face.data(Tok.Typography.Size.xs, .medium))
                .foregroundStyle(Tok.Ink.secondary.color)
                .frame(width: 36, alignment: .leading)
            GeometryReader { geo in
                RoundedRectangle(cornerRadius: Tok.Radius.badge)
                    .fill(Tok.Ink.secondary.color)
                    .frame(width: max(2, geo.size.width * min(1, Self.seconds(value) / top)))
            }
            .frame(height: 8)
            Text(Format.duration(value))
                .font(Tok.Face.data(Tok.Typography.Size.xs))
                .foregroundStyle(Tok.Ink.secondary.color)
                .frame(width: 56, alignment: .trailing)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(label), \(Format.duration(value))")
    }

    private static func seconds(_ d: Duration) -> Double {
        Double(d.components.seconds) + Double(d.components.attoseconds) / 1e18
    }
}
