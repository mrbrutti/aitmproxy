import AitmproxyKit
import Charts
import SwiftUI

/// The Connection page's interactive waterfall (S-064 redesign): one lane per
/// connection (client × authority), each flow a status-colored segment placed by
/// start and duration on a shared time axis. Tap a segment to select its flow and
/// open it in the inspector. Lanes reuse `ConnectionRecord`; segment colour reuses
/// the flow row's dot colour, so the two surfaces never disagree.
struct ConnectionWaterfall: View {
    @Environment(Session.self) private var session

    var body: some View {
        let model = Self.build(rows: session.visibleRows)
        VStack(alignment: .leading, spacing: Space.sm) {
            PageHeader("Connections") {
                Text(model.lanes.count == 1 ? "1 host" : "\(model.lanes.count) hosts")
                    .font(Tok.Face.data(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.tertiary.color)
            }
            .gridProbe("waterfall.title", area: "connection-waterfall")

            if model.segments.isEmpty {
                ContentUnavailableView {
                    Label("No connections yet", systemImage: "point.3.connected.trianglepath.dotted")
                } description: {
                    Text("Connections appear here as clients open them through the proxy.")
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                chart(model)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Tok.Ground.surface.color)
        .gridArea("connection-waterfall", inset: 0)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Connection waterfall")
    }

    private func chart(_ model: Model) -> some View {
        // A fixed row height per lane keeps each Gantt bar a readable thickness
        // instead of collapsing to a hairline when there are many lanes; the chart
        // scrolls when the lanes outgrow the band.
        ScrollView(.vertical) {
            Chart(model.segments) { seg in
                BarMark(
                    xStart: .value("Start", seg.start),
                    xEnd: .value("End", seg.end),
                    y: .value("Connection", seg.lane),
                    height: .fixed(Self.barThickness)
                )
                .foregroundStyle(seg.color)
                .cornerRadius(2)
            }
            .chartYScale(domain: model.lanes)
            .chartYAxis {
                AxisMarks(position: .leading) { value in
                    AxisValueLabel {
                        if let lane = value.as(String.self), let display = model.laneLabel[lane] {
                            Text(display)
                                .font(Tok.Face.data(Tok.Typography.Size.xs))
                                .foregroundStyle(Tok.Ink.secondary.color)
                                // A fixed label gutter so a long authority can't spill
                                // over the earliest segments at the plot's left edge.
                                .frame(width: Self.laneLabelWidth, alignment: .trailing)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                    }
                }
            }
            .chartXAxis {
                AxisMarks { value in
                    AxisGridLine().foregroundStyle(Tok.Line.rule.color)
                    AxisValueLabel {
                        if let date = value.as(Date.self) {
                            Text(Format.time(date))
                                .font(Tok.Face.data(Tok.Typography.Size.xs))
                                .foregroundStyle(Tok.Ink.tertiary.color)
                        }
                    }
                }
            }
            .chartOverlay { proxy in
                GeometryReader { geo in
                    Rectangle()
                        .fill(Color.clear)
                        .contentShape(Rectangle())
                        .onTapGesture { location in select(at: location, proxy: proxy, geo: geo, model: model) }
                }
            }
            .frame(height: max(Self.minChartHeight, CGFloat(model.lanes.count) * Self.laneHeight))
            .padding(.horizontal, Space.md)
            .padding(.bottom, Space.md)
        }
    }

    /// Map a tap to the (time, lane) it lands on and select the flow whose segment
    /// covers it, else the nearest segment in that lane.
    private func select(at location: CGPoint, proxy: ChartProxy, geo: GeometryProxy, model: Model) {
        guard let plot = proxy.plotFrame else { return }
        let origin = geo[plot].origin
        guard let date: Date = proxy.value(atX: location.x - origin.x),
              let lane: String = proxy.value(atY: location.y - origin.y) else { return }
        let inLane = model.segments.filter { $0.lane == lane }
        let hit = inLane.first { $0.start <= date && date <= $0.end }
            ?? inLane.min { abs($0.start.timeIntervalSince(date)) < abs($1.start.timeIntervalSince(date)) }
        if let hit { session.select(hit.id) }
    }

    // MARK: - Model

    private struct Segment: Identifiable {
        let id: FlowID
        let lane: String
        let start: Date
        let end: Date
        let color: Color
    }

    private struct Model {
        var segments: [Segment]
        /// Lane keys in time order (earliest connection first).
        var lanes: [String]
        /// Lane key → the authority shown on the axis.
        var laneLabel: [String: String]
    }

    private static let maxLanes = 16
    /// A fixed per-lane row height and bar thickness so the Gantt stays legible
    /// however many lanes there are; the chart scrolls past the band.
    private static let laneHeight: CGFloat = 28
    private static let barThickness: CGFloat = 20
    private static let minChartHeight: CGFloat = 240
    private static let laneLabelWidth: CGFloat = 152

    /// One lane per authority (host), ordered earliest-first and capped to the
    /// busiest lanes so the axis stays legible. Each flow becomes a segment; a
    /// zero-duration flow (pending/paused/killed) still gets a minimum width.
    private static func build(rows: [FlowRow]) -> Model {
        let timed = rows.filter { $0.startedAt != nil }
        var byAuthority: [String: [FlowRow]] = [:]
        var earliest: [String: Date] = [:]
        for row in timed {
            byAuthority[row.authority, default: []].append(row)
            if let start = row.startedAt {
                earliest[row.authority] = min(earliest[row.authority] ?? start, start)
            }
        }
        let busiest = byAuthority.keys.sorted {
            let (a, b) = (byAuthority[$0]?.count ?? 0, byAuthority[$1]?.count ?? 0)
            return a == b ? (earliest[$0] ?? .distantFuture) < (earliest[$1] ?? .distantFuture) : a > b
        }
        let lanes = Array(busiest.prefix(Self.maxLanes))
            .sorted { (earliest[$0] ?? .distantFuture) < (earliest[$1] ?? .distantFuture) }

        let starts = timed.compactMap(\.startedAt)
        let span = starts.max()?.timeIntervalSince(starts.min() ?? Date()) ?? 1
        let minSeg = max(0.4, span / 120)

        var segments: [Segment] = []
        var laneLabel: [String: String] = [:]
        for authority in lanes {
            laneLabel[authority] = authority
            for row in byAuthority[authority] ?? [] {
                guard let start = row.startedAt else { continue }
                let duration = row.duration.map(Self.seconds) ?? 0
                segments.append(Segment(id: row.id, lane: authority, start: start,
                                        end: start.addingTimeInterval(max(duration, minSeg)),
                                        color: row.dotColor.color))
            }
        }
        return Model(segments: segments, lanes: lanes, laneLabel: laneLabel)
    }

    private static func seconds(_ d: Duration) -> Double {
        Double(d.components.seconds) + Double(d.components.attoseconds) / 1e18
    }
}
