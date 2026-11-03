import AitmproxyKit
import SwiftUI

/// The two wells under the jobs table (Jobs view spec D11, *Wells*): what the job
/// did (Crawl and points) and what it found (Issues), side by side on the resting
/// card chrome. Task 2.6 skeleton: the chrome, the shape of a well and a first set
/// of rows from the Kit's keys; Task 2.9 completes the rows (skip words, lanes with
/// reasons, probes by lane, session, L4, the Issues inks). Every value is the bus's;
/// `—` until the status lands.
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

    private var crawlRows: [(key: String, value: Text)] {
        var rows: [(key: String, value: Text)] = [
            (ScanFormat.WellKey.pagesFetched, number(status?.crawl.pages)),
            (ScanFormat.WellKey.pagesWaiting, number(status?.crawl.queued)),
            (ScanFormat.WellKey.depth, number(status?.crawl.depth)),
            (ScanFormat.WellKey.formsSubmitted, number(status?.crawl.formsSubmitted)),
            (ScanFormat.WellKey.pointsFound, number(summary.points.found)),
            (ScanFormat.WellKey.waitingForAudit, number(summary.points.queued)),
            (ScanFormat.WellKey.audited, number(summary.points.audited)),
            (ScanFormat.WellKey.lanes, text(status.flatMap { laneWords($0.lanes.run) })),
        ]
        if let session = status?.session {
            rows.append((ScanFormat.WellKey.session, text(sessionWords(session))))
        }
        return rows
    }

    // MARK: Issues

    private var issueRows: [(key: String, value: Text)] {
        let by = summary.issues.bySeverity
        let confidence = summary.issues.byConfidence
        return [
            (ScanFormat.WellKey.criticalHighMedium, counts([by.critical, by.high, by.medium])),
            (ScanFormat.WellKey.low, number(by.low)),
            (ScanFormat.WellKey.info, number(by.info)),
            (ScanFormat.WellKey.certainFirmTentative, counts([confidence.certain, confidence.firm, confidence.tentative])),
            (ScanFormat.WellKey.probeErrors, counts([summary.probes.errors, summary.probes.timeouts, summary.probes.rateWaits])),
            (ScanFormat.WellKey.checks, text(status.map { checksWords($0.checks) })),
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

    private func text(_ value: String?) -> Text {
        Text(value ?? ScanFormat.missingValue)
    }

    // MARK: Helpers moved from the old inspector (Task 2.9 wires them into rows)

    /// `HTTP, WebSocket`; nil for none.
    private func laneWords(_ lanes: [ScanLane]) -> String? {
        lanes.isEmpty ? nil : lanes.map(\.word).joined(separator: ", ")
    }

    /// The old Session section as one row: reused · lost · browser partial, in the
    /// Kit's yes / no words. The canary word is Task 2.9's.
    private func sessionWords(_ session: ScanSessionStatus) -> String {
        [session.reused, session.lost, session.browserPartial].map(ScanFormat.yesNo).joined(separator: " · ")
    }

    /// `6,468 · 3,236 · 7 · 3`: scheduled · done · errors · skipped.
    private func checksWords(_ checks: ScanCheckCounters) -> String {
        [checks.scheduled, checks.done, checks.errors, checks.skipped].map(ScanFormat.grouped).joined(separator: " · ")
    }
}

/// One well (D11): a title with its subtitle at the right, then 28 pt key-value
/// rows split by hairlines. Keys read `Tok.Ink.secondary`; values are the data
/// face in `Tok.Ink.primary` unless the caller inked the `Text` itself.
struct ScanWell: View {
    var title: String
    var subtitle: String
    var rows: [(key: String, value: Text)]

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
    }
}
