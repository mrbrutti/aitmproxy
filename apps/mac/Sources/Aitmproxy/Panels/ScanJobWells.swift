import AitmproxyKit
import SwiftUI

/// The two wells under the jobs table (Jobs view spec D11, *Wells*): what the job
/// did (Crawl and points) and what it found (Issues), side by side on the resting
/// card chrome. The rows are the Kit's `ScanFormat.wellRows` (D21): every key a
/// `ScanFormat.WellKey`, every value the bus's, grouped through `ScanFormat.grouped`,
/// `—` until the status lands, and the rows the bus may not have (Crawl errors, Lane
/// skipped, Session, the L4 rows) present only when it does. This view only inks them.
struct ScanJobWells: View {
    var facts: ScanJobFacts

    var body: some View {
        let rows = ScanFormat.wellRows(facts)
        HStack(alignment: .top, spacing: Space.lg) {
            ScanWell(title: ScanFormat.wellCrawlTitle, subtitle: ScanFormat.wellCrawlSubtitle, rows: rows.crawl)
            ScanWell(title: ScanFormat.wellIssuesTitle, subtitle: ScanFormat.wellIssuesSubtitle, rows: rows.issues)
        }
    }
}

/// One well (D11): a title with its subtitle at the right, then 28 pt key-value
/// rows split by hairlines. Keys read `Tok.Ink.secondary`; a row's cells are one
/// `Text` in the data face, each cell in its Kit ink (D21): `.value` in
/// `Tok.Ink.primary`, `.severity` in the severity's colour, `.muted` in
/// `Tok.Ink.tertiary`, the separators in `Tok.Ink.primary`.
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
                    rowText(row)
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

    /// A row's cells as one interpolated `Text` (`+` on `Text` is deprecated on macOS 26):
    /// `ScanFormat.wellCellSeparator` between cells in the primary ink, each cell in its ink.
    private func rowText(_ row: ScanWellRow) -> Text {
        var text = Text(verbatim: "")
        for (index, cell) in row.cells.enumerated() {
            if index > 0 {
                text = Text("\(text)\(Text(verbatim: ScanFormat.wellCellSeparator).foregroundStyle(Tok.Ink.primary.color))")
            }
            text = Text("\(text)\(Text(verbatim: cell.text).foregroundStyle(ink(cell.ink)))")
        }
        return text
    }

    /// The Kit's ink → the token colour (D21).
    private func ink(_ ink: ScanWellCell.Ink) -> Color {
        switch ink {
        case .value: Tok.Ink.primary.color
        case .severity(let level): ScanToneColors.severity(level)
        case .muted: Tok.Ink.tertiary.color
        }
    }
}
