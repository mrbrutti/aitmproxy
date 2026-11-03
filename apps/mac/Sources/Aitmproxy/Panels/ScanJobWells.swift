import AitmproxyKit
import SwiftUI

/// One key-value row of a well: the key in the UI face, the value a `Text` the caller
/// may have inked itself (the Issues well's severity counts).
typealias ScanWellRow = (key: String, value: Text)

/// The two wells under the jobs table (Jobs view spec D11, *Wells*): what the job
/// did (Crawl and points) and what it found (Issues), side by side on the resting
/// card chrome. Every key is a `ScanFormat.WellKey`; every value is the bus's, grouped
/// through `ScanFormat.grouped`, `—` until the status lands. Rows the bus may not have
/// are conditional: Crawl errors only when > 0, one `Lane skipped` row per skipped
/// lane, Session only when the status carries one, the four L4 rows only when an L4
/// lane ran.
struct ScanJobWells: View {
    var facts: ScanJobFacts

    private var summary: ScanJobSummary { facts.summary }
    private var status: ScanJobStatus? { facts.status }

    var body: some View {
        HStack(alignment: .top, spacing: Space.lg) {
            ScanWell(title: ScanFormat.wellCrawlTitle, subtitle: ScanFormat.wellCrawlSubtitle, rows: crawlRows)
            ScanWell(title: ScanFormat.wellIssuesTitle, subtitle: ScanFormat.wellIssuesSubtitle, rows: issueRows)
        }
    }

    // MARK: Crawl and points

    private var crawlRows: [ScanWellRow] {
        typealias Key = ScanFormat.WellKey
        var rows: [ScanWellRow] = [
            (Key.pagesFetched, number(status?.crawl.pages)),
            (Key.pagesWaiting, number(status?.crawl.queued)),
            (Key.depth, number(status?.crawl.depth)),
            (Key.formsSubmitted, number(status?.crawl.formsSubmitted)),
            (Key.formsNotSubmitted, number(status?.crawl.formsSkipped)),
        ]
        if let errors = status?.crawl.errors, errors > 0 {
            rows.append((Key.crawlErrors, number(errors)))
        }
        rows += [
            (Key.pointsFound, number(summary.points.found)),
            (Key.waitingForAudit, number(summary.points.queued)),
            (Key.audited, number(summary.points.audited)),
        ]
        rows += ScanFormat.pointSkipWords(summary.points.skipped).map(skipRow)
        rows.append((Key.lanes, text(status.flatMap { laneWords($0.lanes.run) })))
        rows += (status?.lanes.skipped ?? []).map { (Key.laneSkipped, Text(ScanFormat.skippedLaneWords($0))) }
        rows.append((Key.probesByLane, text(probesByLaneWords(summary.probes.byLane))))
        if let session = status?.session {
            rows.append((Key.session, Text(sessionWords(session))))
        }
        if let l4 = status?.l4 {
            rows += [
                (Key.l4Cases, number(l4.cases)),
                (Key.l4Crashes, number(l4.crashes)),
                (Key.l4LivenessFailures, number(l4.livenessFailures)),
                (Key.l4RetiredElements, number(l4.retiredElements)),
            ]
        }
        return rows
    }

    // MARK: Issues

    private var issueRows: [ScanWellRow] {
        typealias Key = ScanFormat.WellKey
        let by = summary.issues.bySeverity
        let confidence = summary.issues.byConfidence
        return [
            (Key.criticalHighMedium, Text("\(severityCount(.critical, by.critical)) · \(severityCount(.high, by.high)) · \(severityCount(.medium, by.medium))")),
            (Key.low, severityCount(.low, by.low)),
            (Key.info, severityCount(.info, by.info)),
            (Key.certainFirmTentative, counts([confidence.certain, confidence.firm, confidence.tentative])),
            (Key.probeErrors, counts([summary.probes.errors, summary.probes.timeouts, summary.probes.rateWaits])),
            (Key.checks, text(status.map { checksWords($0.checks) })),
        ]
    }

    // MARK: Values

    /// A grouped number, or the Kit's missing mark before the status lands.
    private func number(_ value: Int?) -> Text {
        text(value.map(ScanFormat.grouped))
    }

    /// `0 · 0 · 0`: several counts in one cell, each grouped.
    private func counts(_ values: [Int]) -> Text {
        text(values.map(ScanFormat.grouped).joined(separator: " · "))
    }

    /// One severity tally in its severity's ink when > 0, `Tok.Ink.tertiary` when 0 (D11);
    /// the `Critical · High · Medium` row interpolates three, its separators in the row's ink.
    private func severityCount(_ severity: ScanSeverity, _ count: Int) -> Text {
        Text(ScanFormat.grouped(count))
            .foregroundStyle(count > 0 ? ScanToneColors.severity(severity) : Tok.Ink.tertiary.color)
    }

    private func text(_ value: String?) -> Text {
        Text(value ?? ScanFormat.missingValue)
    }

    // MARK: Row words

    /// `722 skipped as repetitive` → key `skipped as repetitive`, value `722`: the Kit's
    /// sentence split at its first space so the count sits in the data column with the
    /// other numbers.
    private func skipRow(_ sentence: String) -> ScanWellRow {
        guard let space = sentence.firstIndex(of: " ") else { return (sentence, Text(verbatim: "")) }
        return (String(sentence[sentence.index(after: space)...]), Text(sentence[..<space]))
    }

    /// `HTTP, WebSocket`; nil for none.
    private func laneWords(_ lanes: [ScanLane]) -> String? {
        lanes.isEmpty ? nil : lanes.map(\.word).joined(separator: ", ")
    }

    /// `HTTP 240 · WebSocket 47`, lanes in the Kit's order (HTTP, WebSocket, L4 packet,
    /// L4 stream, then anything newer by wire name); nil when the bus listed none.
    private func probesByLaneWords(_ byLane: [String: Int]) -> String? {
        guard !byLane.isEmpty else { return nil }
        return byLane.keys
            .compactMap(ScanLane.init(rawValue:))
            .sorted { (laneOrder($0), $0.rawValue) < (laneOrder($1), $1.rawValue) }
            .map { "\($0.word) \(ScanFormat.grouped(byLane[$0.rawValue] ?? 0))" }
            .joined(separator: " · ")
    }

    private func laneOrder(_ lane: ScanLane) -> Int {
        switch lane {
        case .http: 0
        case .ws: 1
        case .l4Packet: 2
        case .l4Stream: 3
        case .other: 4
        }
    }

    /// `no · no · ok · no`: reused · lost · canary · browser partial, in the Kit's words.
    private func sessionWords(_ session: ScanSessionStatus) -> String {
        [
            ScanFormat.yesNo(session.reused), ScanFormat.yesNo(session.lost),
            ScanFormat.canaryWord(session.canary), ScanFormat.yesNo(session.browserPartial),
        ].joined(separator: " · ")
    }

    /// `6,468 · 3,236 · 7 · 3`: scheduled · done · errors · skipped.
    private func checksWords(_ checks: ScanCheckCounters) -> String {
        [checks.scheduled, checks.done, checks.errors, checks.skipped].map(ScanFormat.grouped).joined(separator: " · ")
    }
}

/// One well (D11): a title with its subtitle at the right, then 28 pt key-value
/// rows split by hairlines. Keys read `Tok.Ink.secondary`; values are the data
/// face in `Tok.Ink.primary` unless the caller inked the `Text` itself.
/// Accessibility: the well is a container labelled by its title; each row is one
/// element reading `key, value` (a well may hold twenty rows, too many for one value).
struct ScanWell: View {
    var title: String
    var subtitle: String
    var rows: [ScanWellRow]

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline, spacing: Space.sm) {
                Text(title)
                    .font(Tok.Face.ui(Tok.Typography.Size.base, .medium))
                    .foregroundStyle(Tok.Ink.primary.color)
                Spacer(minLength: Space.sm)
                Text(subtitle)
                    .font(Tok.Face.ui(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.tertiary.color)
            }
            .padding(.bottom, Tok.Metric.gapTight)
            .accessibilityElement(children: .combine)
            .accessibilityAddTraits(.isHeader)
            ForEach(Array(rows.enumerated()), id: \.offset) { _, row in
                Rule(color: Tok.Line.rule)
                HStack(spacing: Space.sm) {
                    Text(row.key)
                        .font(Tok.Face.ui(Tok.Typography.Size.md))
                        .foregroundStyle(Tok.Ink.secondary.color)
                    Spacer(minLength: Space.sm)
                    row.value
                        .font(Tok.Face.data(Tok.Typography.Size.md))
                        .foregroundStyle(Tok.Ink.primary.color)
                        .monospacedDigit()
                        .lineLimit(1)
                }
                .frame(height: Tok.Size.control)
                .accessibilityElement(children: .combine)
            }
        }
        .padding(.vertical, Space.lg)
        .padding(.horizontal, Space.xl)
        .frame(maxWidth: .infinity, alignment: .leading)
        .scanCardChrome(shadow: Tok.Shadow.rest)
        .accessibilityElement(children: .contain)
        .accessibilityLabel(title)
    }
}
