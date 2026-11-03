import AitmproxyKit
import SwiftUI

/// The Scan page's Jobs tab (Jobs view spec, UX *Surface*; D10, D11, D15): one
/// scrolling column, top to bottom: the bus banner when the link is away, the
/// selected job's card, the jobs table, the two wells. Every number on this tab is
/// a value the bus returned or the Kit derived from one; the view computes none.
/// Reduce Motion is read here once and passed down (D12). Task 2.6 skeleton: the
/// column and its plumbing; Task 2.7 rebuilds the table's rows (the PR 1 rows stay
/// meanwhile), Task 2.8 the card's blocks, Task 2.9 the wells' rows.
struct ScanJobsTab: View {
    @Bindable var state: ScanPanelState
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @FocusState private var listFocused: Bool
    /// The card's first enabled verb takes focus when true (D14): Return or → in
    /// the table sets it (Task 2.7); Escape from the card clears it.
    @FocusState private var inspectorFocused: Bool
    /// The row under the pointer, so only it shows its hover Cancel button.
    @State private var hoveredJob: String?

    /// The entrance generation the card and the wells key on (D12). Task 2.5 adds
    /// `ScanPanelState.entranceGeneration`; until it lands this never moves, so no
    /// entrance fires. The one line to change: read `state.entranceGeneration`.
    private var entranceGeneration: Int { 0 }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Space.xl) {
                if let banner = state.link.bannerText {
                    // The bus is away (D15): nothing failed, so the banner reads in
                    // secondary ink on raised, not the error ink.
                    ScanJobsBanner(text: banner)
                }
                if let error = state.surface.inlineJobsError(ageMs: state.link.valuesAgeMs) {
                    // The inline read error (D6): the values it could not refresh stay,
                    // and a failed list says how old its values are.
                    ScanInlineError(text: error, inset: 0)
                }
                if state.surface.jobs.isEmpty {
                    ContentUnavailableView {
                        Label(scanNoJobsText, systemImage: Tok.Glyph.search)
                    } actions: {
                        FlatButton("Open Profiles") { state.surface.tab = .profiles }
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, Space.section)
                } else {
                    if let job = state.surface.selectedJob, let facts = state.surface.facts(for: job) {
                        ScanJobCard(
                            state: state,
                            facts: facts,
                            progress: ScanJobProgress(facts),
                            link: state.link,
                            reduceMotion: reduceMotion,
                            generation: entranceGeneration,
                            inspectorFocused: $inspectorFocused,
                            onEscape: { listFocused = true }
                        )
                    }
                    table
                    if let job = state.surface.selectedJob, let facts = state.surface.facts(for: job) {
                        ScanJobWells(facts: facts)
                            .cardEntrance(index: 3, generation: entranceGeneration, reduceMotion: reduceMotion)
                    }
                }
            }
            .padding(.horizontal, Space.xxl)
            .padding(.top, Space.xl)
            .padding(.bottom, Space.section)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Tok.Ground.surface.color)
    }

    // MARK: Table

    /// The jobs table: PR 1's rows for now (Task 2.7 brings D10's header, columns,
    /// selection edge and hover Cancel). Every row reads the Kit's merged facts (D2):
    /// the list row and the stored status, reconciled once, so the row and the card
    /// never disagree. Arrow keys walk the selection once the table has focus (D13),
    /// with no animation and no entrance (D12).
    private var table: some View {
        VStack(spacing: 0) {
            ForEach(state.surface.jobs, id: \.job) { summary in
                if let facts = state.surface.facts(for: summary.job) {
                    ScanJobRow(
                        facts: facts,
                        selected: facts.job == state.surface.selectedJob,
                        hovered: facts.job == hoveredJob,
                        cancelable: mayCancel(facts.job),
                        select: { select(facts.job) },
                        cancel: { cancel(facts.job) }
                    )
                    .contentShape(Rectangle())
                    .onTapGesture { select(facts.job) }
                    .onHover { inside in
                        if inside {
                            hoveredJob = facts.job
                        } else if hoveredJob == facts.job {
                            hoveredJob = nil
                        }
                    }
                    .contextMenu { rowMenu(facts.job) }
                }
            }
        }
        .focusable()
        .focused($listFocused)
        .focusEffectDisabled()
        .onMoveCommand { direction in
            // Keyboard selection never animates (D12): no eases, no entrance.
            withTransaction(Transaction(animation: nil)) {
                switch direction {
                case .up: state.surface.moveSelection(in: .jobs, by: -1)
                case .down: state.surface.moveSelection(in: .jobs, by: 1)
                default: break
                }
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Jobs")
        .gridProbe("scan-jobs-table", area: "scan")
    }

    /// The row's verbs (D5): Cancel Scan while the job can still be stopped and the
    /// link is live, the two tab jumps, and the id for a terminal or a bug report.
    @ViewBuilder private func rowMenu(_ job: String) -> some View {
        if mayCancel(job) {
            Button("Cancel Scan") { cancel(job) }
        }
        Button("Show Issues") { state.showIssues(job: job) }
        Button("Show Site Map") { state.showSitemap(job: job) }
        Divider()
        Button("Copy Job ID") { Pasteboard.copy(job) }
    }

    /// Whether a row may offer Cancel: the Kit's predicate on the merged state
    /// (queued or running; never cancelling or terminal, Jobs view D2) and the
    /// link's verb gate (Jobs view D6).
    private func mayCancel(_ job: String) -> Bool {
        state.surface.mayCancel(job: job) && state.verbsEnabled
    }

    /// A pointer selection. Task 2.5 routes this through `state.select(_:cause: .pointer)`
    /// so the card's entrance fires; until it lands the surface's bare select stands.
    private func select(_ job: String) {
        state.surface.select(job: job)
        listFocused = true
    }

    private func cancel(_ job: String) {
        Task { await state.cancel(job: job) }
    }
}

// MARK: - Banner

/// The bus-away banner (D15): the Kit's sentence in `Tok.Ink.secondary` on
/// `Tok.Ground.raised`, `ScanInlineError`'s shape without the error ink.
private struct ScanJobsBanner: View {
    var text: String

    var body: some View {
        Text(text)
            .font(Tok.Face.ui(Tok.Typography.Size.sm))
            .foregroundStyle(Tok.Ink.secondary.color)
            .lineLimit(2)
            .textSelection(.enabled)
            .padding(.horizontal, Space.md)
            .padding(.vertical, Space.sm)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Tok.Ground.raised.color, in: RoundedRectangle(cornerRadius: Tok.Radius.panel))
    }
}

// MARK: - Row (PR 1; Task 2.7 replaces)

/// One job (D5): `<State or phase> · <profile> · <hosts>` over the probe / point /
/// elapsed line, then the severity bar. The counters are the merged facts' (Jobs
/// view D2); the profile name and hosts come from `scan.status`, so a job whose
/// status has not been read yet shows `—` for them. The row is one accessibility
/// element with the button trait, the selected trait while selected, a `Select`
/// action and the identifier `scan-job-<id>` (Jobs view D5).
private struct ScanJobRow: View {
    var facts: ScanJobFacts
    var selected: Bool
    var hovered: Bool
    /// Whether the hover Cancel shows: the merged state is queued or running and
    /// the link is live (Jobs view D2, D6).
    var cancelable: Bool
    var select: () -> Void
    var cancel: () -> Void

    private var summary: ScanJobSummary { facts.summary }

    var body: some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            HStack(spacing: Space.sm) {
                Text(ScanFormat.jobRowLine1(summary, status: facts.status))
                    .font(Tok.Face.ui(Tok.Typography.Size.md, .medium))
                    .foregroundStyle(Tok.Ink.primary.color)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer(minLength: Space.xs)
                if hovered, cancelable {
                    FlatButton("Cancel", action: cancel)
                        .help(ScanFormat.cancelHelpText)
                }
            }
            // The line keeps the button's height whether or not it shows, so a
            // hover never moves the rows below.
            .frame(height: Tok.Size.control)
            Text(ScanFormat.jobRowLine2(summary))
                .font(Tok.Face.data(Tok.Typography.Size.sm))
                .foregroundStyle(Tok.Ink.secondary.color)
                .lineLimit(1)
            ScanSeverityBar(by: summary.issues.bySeverity, height: 6) // grid: ok spec D5 fixes the row bar at 6 pt
        }
        .padding(.horizontal, Space.md)
        .padding(.vertical, Space.sm)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(selected ? Tok.Ground.active.color : .clear)
        .overlay(alignment: .bottom) { Rule(color: Tok.Line.rule) }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(ScanFormat.jobAccessibilityLabel(summary, status: facts.status))
        .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
        .accessibilityAction { select() }
        .accessibilityAction(named: "Select") { select() }
        .accessibilityIdentifier("scan-job-\(facts.job)")
    }
}

// MARK: - Severity bar (Task 2.10 removes)

/// A stacked bar of an issue tally (D5): one `Rectangle` per non-zero severity,
/// width proportional to its share, in that severity's `Tok.Severity` ink; the
/// total as a number at the end; a 1 pt rule when there is nothing to show. It
/// hides from VoiceOver because the row label already reads the counts in words
/// (D13: severity never by colour alone).
struct ScanSeverityBar: View {
    var by: BySeverity
    var height: CGFloat

    private var segments: [ScanSeveritySegment] { ScanSurfaceModel.severityBarSegments(by) }

    var body: some View {
        HStack(spacing: Space.sm) {
            Group {
                if segments.isEmpty {
                    Rule(color: Tok.Line.border)
                } else {
                    GeometryReader { geo in
                        // The 1 pt seams between segments come out of the width first,
                        // so the shares still sum to the bar and never overflow it.
                        let usable = max(0, geo.size.width - CGFloat(segments.count - 1))
                        HStack(spacing: 1) {
                            ForEach(segments, id: \.severity) { segment in
                                Rectangle()
                                    .fill(ScanToneColors.severity(segment.severity))
                                    .frame(width: max(1, usable * segment.fraction))
                            }
                        }
                    }
                }
            }
            .frame(height: height)
            .frame(maxWidth: .infinity)
            Text("\(by.total)")
                .font(Tok.Face.data(Tok.Typography.Size.sm, .medium))
                .foregroundStyle(Tok.Ink.secondary.color)
                .frame(width: 32, alignment: .trailing)
        }
        .accessibilityHidden(true)
    }
}
