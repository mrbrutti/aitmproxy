import AitmproxyKit
import SwiftUI

// MARK: - Comp constants

/// The locked comp's geometric constants that are not tokens (Jobs view spec D11;
/// `docs/design/mockup/scan-jobs/committed.html`), each named after the CSS rule
/// it comes from. Everything else the Jobs views draw is a `Tok.*` or `ScanMotion`
/// token (AC22). Internal rather than private because `ScanProgressViews.swift`
/// draws the ring, the dots, the chip and the entrance from the same numbers.
enum CardMetrics {
    /// `.card::before { width: 3px }` — the card's tone edge; also the selected row's edge (D10).
    static let edge: CGFloat = 3
    /// `.now { width: 2px }` — the lane's now mark.
    static let nowMark: CGFloat = 2
    /// `.now { top: -10px; bottom: -10px }` — how far the mark overshoots the track.
    static let nowOvershoot: CGFloat = 10
    /// `.now::after { width: 10px; height: 10px }` — the breathing dot on the mark.
    static let nowDot: CGFloat = 10
    /// `.now { box-shadow: 0 0 0 3px rgba(230,230,232,.12) }` — the mark's halo width …
    static let haloWidth: CGFloat = 3
    /// … and the halo's opacity from the same rule.
    static let haloOpacity: Double = 0.12
    /// `.chip i`, `.who`, `.pend`, `.ok { width: 6px; height: 6px }` — the state, chip and agent dots.
    static let dot: CGFloat = 6
    /// `.who { box-shadow: 0 0 0 3px var(--agent-tint) }` — the agent dot's halo.
    static let dotHalo: CGFloat = 3
    /// `.gauge { height: 3px }` — the probe budget gauge.
    static let gauge: CGFloat = 3
    /// `.group i { width: 8px }` — one ledger mark's width …
    static let markWidth: CGFloat = 8
    /// `.group i { height: 16px }` — … its height …
    static let markHeight: CGFloat = 16
    /// `.group i { border-radius: 2px }` — … and its corner.
    static let markRadius: CGFloat = 2
    /// `<circle stroke-width="2.5">` in `.ring` — the row's progress ring.
    static let ringStroke: CGFloat = 2.5
    /// `.ring .arc { transform: rotate(-90 9 9) }` — the arc starts at twelve o'clock.
    static let ringStart: Double = -90
    /// `.seg.crawl` — the crawl cap is as wide as its labels, about 80 pt (D11 §2: the
    /// bus carries no crawl duration, so the cap is layout, not a proportion).
    static let crawlCapWidth: CGFloat = 80
    /// `td { height: 46px }` on the 4 pt grid — the row pitch (D10).
    static let rowPitch: CGFloat = 44
    /// `th { height: 32px }` — the table header.
    static let headerHeight: CGFloat = 32
    /// `th:last-child, td:last-child { width: 84px }` — the trailing action column.
    static let actionColumn: CGFloat = 84
    /// `.enter { transform: translateY(8px) }` — the entrance's rise.
    static let entranceRise: CGFloat = 8
    /// `@keyframes breathe { to { opacity: .4 } }` — the breathing floor.
    static let breathFloor: Double = 0.4
    /// `.chip { padding: 0 9px }` — the chip's horizontal padding (its 22 pt height is `Tok.Metric.chip`).
    static let chipPadding: CGFloat = 9
}

// MARK: - Card

/// The selected job's card (Jobs view D11): the inspect-and-act surface at the top
/// of the Jobs column, on the raised chrome with a 3 pt edge in the job's tone.
/// Task 2.6 skeleton: the chrome, the edge, the entrance plumbing and the six
/// sub-views as stubs that render their facts as plain text; Task 2.8 fills them
/// (D9, D11–D14). The card reads the merged facts (D2) and the derived progress
/// (D8) and computes no number of its own.
struct ScanJobCard: View {
    @Bindable var state: ScanPanelState
    var facts: ScanJobFacts
    var progress: ScanJobProgress
    var link: ScanJobsLink
    var reduceMotion: Bool
    /// The tab's entrance generation (D12): the card's blocks enter when it changes.
    var generation: Int
    /// The card's first enabled verb takes focus when the tab sets this (D14).
    var inspectorFocused: FocusState<Bool>.Binding
    /// Escape from the verbs: the tab returns focus to the table (D14).
    var onEscape: () -> Void

    private var tone: ScanJobTone { ScanFormat.tone(facts) }

    var body: some View {
        VStack(alignment: .leading, spacing: Space.lg) {
            ScanJobTitleRow(state: state, facts: facts, link: link, inspectorFocused: inspectorFocused, onEscape: onEscape)
                .cardEntrance(index: 0, generation: generation, reduceMotion: reduceMotion)
            VStack(alignment: .leading, spacing: Space.md) {
                ScanJobLane(progress: progress, facts: facts, reduceMotion: reduceMotion)
                ScanIssueLedger(
                    groups: ScanFormat.ledgerGroups(by: facts.summary.issues.bySeverity),
                    running: !facts.summary.state.isTerminal)
                ScanProbeGauge(sent: facts.summary.probes.sent, budget: facts.summary.probes.budget)
            }
            .cardEntrance(index: 1, generation: generation, reduceMotion: reduceMotion)
            ScanKPIStrip(facts: facts, progress: progress)
                .cardEntrance(index: 2, generation: generation, reduceMotion: reduceMotion)
            ScanAttentionBlock(facts: facts, launchNotices: state.surface.launchNotices[facts.job] ?? [])
        }
        .padding(.vertical, Space.xl)
        .padding(.horizontal, Space.xxl)
        .frame(maxWidth: .infinity, alignment: .leading)
        .overlay(alignment: .leading) {
            // The tone edge, recoloured over `ScanMotion.state` on a state change (D12);
            // the chrome's clip rounds its ends to the card's corners.
            Rectangle()
                .fill(ScanToneColors.edge(tone))
                .frame(width: CardMetrics.edge)
                .animation(ScanMotion.ease(ScanMotion.state), value: tone)
        }
        .scanCardChrome(shadow: Tok.Shadow.float)
        .gridProbe("scan-job-card", area: "scan")
    }
}

// MARK: - Title row (stub; Task 2.8)

/// The card's title row (D11 §1): the state chip, the host heading, the finding
/// line and the verbs. Stub: the chip and heading are final; the finding line is
/// its plain `text`; the verbs are PR 1's (Cancel Scan / Cancelling…, Show Issues,
/// Show Site Map). Task 2.8 inks the line's parts, adds Scan Again and the
/// `Unable to scan again` line, and gates the slot by `link.verbsEnabled`.
struct ScanJobTitleRow: View {
    @Bindable var state: ScanPanelState
    var facts: ScanJobFacts
    var link: ScanJobsLink
    var inspectorFocused: FocusState<Bool>.Binding
    var onEscape: () -> Void

    private var line: ScanFindingLine { ScanFormat.findingLine(facts, timeZone: .current) }

    var body: some View {
        HStack(alignment: .top, spacing: Space.md) {
            VStack(alignment: .leading, spacing: Space.xs) {
                HStack(spacing: Space.md) {
                    ScanStateChip(word: ScanFormat.stateWord(facts), tone: ScanFormat.tone(facts))
                    Text(ScanFormat.jobHeading(facts))
                        .font(Tok.Face.data(Tok.Typography.Size.xxl, .semibold))
                        .foregroundStyle(Tok.Ink.primary.color)
                        .lineLimit(1)
                        .help(ScanFormat.jobHeadingHelp(facts) ?? "")
                        .accessibilityAddTraits(.isHeader)
                }
                if let reason = line.reason {
                    findingText(reason)
                }
                findingText(line.text)
            }
            Spacer(minLength: Space.sm)
            verbs
        }
    }

    private func findingText(_ text: String) -> some View {
        Text(text)
            .font(Tok.Face.ui(Tok.Typography.Size.base))
            .foregroundStyle(Tok.Ink.secondary.color)
            .fixedSize(horizontal: false, vertical: true)
    }

    /// PR 1's verbs, carried over: Cancel Scan while the merged state is queued or
    /// running, disabled and titled by the cancelling word while a cancel is on the
    /// wire or the core calls the job cancelling (D2), off while the link is not
    /// live (D6); the two tab jumps. Task 2.8 adds Scan Again for a terminal job.
    private var verbs: some View {
        HStack(spacing: Space.sm) {
            FlatButton("Show Site Map") { state.showSitemap(job: facts.job) }
                .focused(inspectorFocused)
            FlatButton("Show Issues") { state.showIssues(job: facts.job) }
            switch facts.summary.state {
            case .queued, .running:
                if state.cancelInFlight(facts.job) {
                    cancellingButton
                } else {
                    PrimaryButton("Cancel Scan") { Task { await state.cancel(job: facts.job) } }
                        .keyboardShortcut(".", modifiers: [.command, .option])
                        .help(ScanFormat.cancelHelpText)
                        .disabled(!link.verbsEnabled)
                }
            case .cancelling:
                cancellingButton
            default:
                EmptyView()
            }
        }
        .frame(height: Tok.Size.controlLg)
        .onExitCommand(perform: onEscape)
    }

    private var cancellingButton: some View {
        PrimaryButton(ScanFormat.cancellingTitle) {}
            .disabled(true)
    }
}

// MARK: - Lane (stub; Task 2.8)

/// The scan lane (D11 §2; the spec names it `ScanLane`, which is the Kit's lane enum, so
/// the view is `ScanJobLane`). Stub: the 64 pt raised track carrying the phase line or
/// the end sentence as text, the now tag and the scale row beneath. Task 2.8 draws
/// the crawl cap, the audit fill, the now mark and the end swap.
struct ScanJobLane: View {
    var progress: ScanJobProgress
    var facts: ScanJobFacts
    var reduceMotion: Bool

    private var trackText: String {
        facts.summary.state.isTerminal ? (ScanEndText.sentence(facts) ?? "") : progress.phaseLine
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Space.sm) {
            Text(trackText)
                .font(Tok.Face.ui(Tok.Typography.Size.md))
                .foregroundStyle(Tok.Ink.secondary.color)
                .padding(.horizontal, Space.md)
                .frame(maxWidth: .infinity, minHeight: Tok.Size.Row.card, alignment: .leading)
                .background(Tok.Ground.raised.color, in: RoundedRectangle(cornerRadius: Tok.Radius.panel))
            if let tag = progress.nowTag {
                Text(tag)
                    .font(Tok.Face.ui(Tok.Typography.Size.sm))
                    .foregroundStyle(Tok.Ink.secondary.color)
            }
            HStack(spacing: Space.lg) {
                Text(ScanFormat.scaleElapsed(ms: facts.summary.elapsedMs))
                if let estimate = progress.estimateText {
                    Text(estimate).help(progress.estimateHelp ?? "")
                }
            }
            .font(Tok.Face.ui(Tok.Typography.Size.sm))
            .foregroundStyle(Tok.Ink.tertiary.color)
        }
        .help(progress.helpText)
    }
}

// MARK: - Ledger (stub; Task 2.8)

/// The issue ledger (D11 §3). Stub: the count words in their severity inks, or the
/// Kit's empty words. Task 2.8 draws the marks and their arrival.
struct ScanIssueLedger: View {
    var groups: [ScanLedgerGroup]
    var running: Bool

    var body: some View {
        HStack(spacing: Space.lg) {
            if groups.isEmpty {
                Text(ScanFormat.severityWords(by: .zero, running: running))
                    .foregroundStyle(Tok.Ink.tertiary.color)
            } else {
                ForEach(groups, id: \.severity) { group in
                    Text(group.word)
                        .foregroundStyle(ScanToneColors.severity(group.severity))
                }
            }
        }
        .font(Tok.Face.ui(Tok.Typography.Size.sm, .medium))
        .frame(minHeight: Space.xl)
    }
}

// MARK: - Gauge (stub; Task 2.8)

/// The probe budget gauge (D11 §4). Stub: the label and the Kit's text. Task 2.8
/// draws the 3 pt track and its warning colour.
struct ScanProbeGauge: View {
    var sent: Int
    var budget: Int

    var body: some View {
        HStack(spacing: Space.md) {
            Text(ScanFormat.gaugeLabel)
                .font(Tok.Face.ui(Tok.Typography.Size.sm))
            Text(ScanFormat.probeBudgetText(sent: sent, budget: budget))
                .font(Tok.Face.data(Tok.Typography.Size.sm))
                .monospacedDigit()
        }
        .foregroundStyle(Tok.Ink.secondary.color)
        .help(ScanFormat.probesTileHelp(sent: sent, budget: budget))
    }
}

// MARK: - KPI strip (stub; Task 2.8)

/// The KPI strip (D11 §5): five cells in one bordered container. Stub: label over
/// value as plain text, units beside. Task 2.8 sizes the numerals, ticks them and
/// adds the hover and accessibility.
struct ScanKPIStrip: View {
    var facts: ScanJobFacts
    var progress: ScanJobProgress

    private var summary: ScanJobSummary { facts.summary }
    private var checks: ScanCheckCounters? { facts.status?.checks }

    var body: some View {
        HStack(spacing: 0) {
            cell(ScanFormat.kpiLabels[0], progress.percentText ?? ScanFormat.missingValue, nil)
            VRule(color: Tok.Line.border)
            cell(
                ScanFormat.kpiLabels[1],
                checks.map { ScanFormat.grouped($0.done) } ?? ScanFormat.missingValue,
                checks.map { ScanFormat.ofText($0.scheduled) })
            VRule(color: Tok.Line.border)
            cell(ScanFormat.kpiLabels[2], ScanFormat.grouped(summary.probes.sent), ScanFormat.ofText(summary.probes.budget))
            VRule(color: Tok.Line.border)
            cell(ScanFormat.kpiLabels[3], ScanFormat.grouped(summary.points.audited), ScanFormat.ofText(summary.points.found))
            VRule(color: Tok.Line.border)
            cell(
                ScanFormat.kpiLabels[4], ScanFormat.grouped(summary.issues.bySeverity.total),
                ScanFormat.severityWords(by: summary.issues.bySeverity, running: !summary.state.isTerminal))
        }
        .background(Tok.Ground.surface.color, in: RoundedRectangle(cornerRadius: Tok.Radius.panel))
        .overlay(RoundedRectangle(cornerRadius: Tok.Radius.panel).strokeBorder(Tok.Line.border.color))
    }

    private func cell(_ label: String, _ value: String, _ unit: String?) -> some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            Text(label)
                .font(Tok.Face.ui(Tok.Typography.Size.md))
                .foregroundStyle(Tok.Ink.secondary.color)
            HStack(alignment: .firstTextBaseline, spacing: Space.sm) {
                Text(value)
                    .font(Tok.Face.data(Tok.Typography.Size.display))
                    .foregroundStyle(Tok.Ink.primary.color)
                    .monospacedDigit()
                if let unit {
                    Text(unit)
                        .font(Tok.Face.ui(Tok.Typography.Size.md))
                        .foregroundStyle(Tok.Ink.secondary.color)
                }
            }
        }
        .padding(.horizontal, Space.lg)
        .padding(.vertical, Space.md)
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
    }
}

// MARK: - Attention block (stub; Task 2.8)

/// The attention block (D9, D11 §6): what needs the operator's eye, only when there
/// is something. Stub: the Kit's lines as plain text (the samples' first details
/// inline), the error verbatim, the raw lines, the notices. Task 2.8 puts the
/// samples behind `DisclosureGroup`s.
struct ScanAttentionBlock: View {
    var facts: ScanJobFacts
    var launchNotices: [String]

    private var status: ScanJobStatus? { facts.status }
    private var lines: [ScanAttentionLine] { ScanEndText.attention(facts) }
    private var notices: [String] { status.map { ScanEndText.notices($0, launchNotices: launchNotices) } ?? [] }
    private var rawLines: [String] {
        var raw: [String] = []
        if let reason = status?.stoppedReason { raw.append(ScanEndText.rawReasonLine(reason)) }
        if let kind = status?.crawl.lastError { raw.append(ScanEndText.rawCrawlErrorLine(kind)) }
        return raw
    }

    private var isEmpty: Bool { lines.isEmpty && status?.error == nil && rawLines.isEmpty && notices.isEmpty }

    var body: some View {
        if !isEmpty {
            VStack(alignment: .leading, spacing: Space.sm) {
                ForEach(Array(lines.enumerated()), id: \.offset) { _, line in
                    Text(line.text)
                        .font(Tok.Face.ui(Tok.Typography.Size.md))
                        .foregroundStyle(Tok.Ink.primary.color)
                }
                if let error = status?.error {
                    Text(error)
                        .font(Tok.Face.data(Tok.Typography.Size.md))
                        .foregroundStyle(Tok.Status.serverError.color)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
                ForEach(rawLines, id: \.self) { raw in
                    Text(raw)
                        .font(Tok.Face.data(Tok.Typography.Size.xs))
                        .foregroundStyle(Tok.Ink.tertiary.color)
                        .textSelection(.enabled)
                }
                if !notices.isEmpty {
                    ScanSectionTitle("Notices")
                    ForEach(Array(notices.enumerated()), id: \.offset) { _, notice in
                        Text(notice)
                            .font(Tok.Face.ui(Tok.Typography.Size.sm))
                            .foregroundStyle(Tok.Ink.secondary.color)
                            .textSelection(.enabled)
                    }
                }
            }
        }
    }
}
